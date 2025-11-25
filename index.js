// Listar solicitações
app.get('/solicitacoes', authMiddleware, async (req, res) => {
  try {
    const { id, tipo } = req.user;

    let result;
    if (tipo === 'admin') {
      // Admin enxerga todas
      result = await db.query(
        `SELECT
           s.*,
           u.nome AS usuario_nome,
           u.email AS usuario_email,
           (
             SELECT COUNT(*)::int
             FROM solicitacao_arquivos a
             WHERE a.solicitacao_id = s.id
           ) AS "docsExtrasCount",
           (
             SELECT COALESCE(
               json_agg(
                 json_build_object(
                   'status', h.status,
                   'date', h.data_movimentacao,
                   'origem', COALESCE(h.origem, 'API'),
                   'obs', COALESCE(h.obs, '')
                 )
                 ORDER BY h.data_movimentacao
               ),
               '[]'::json
             )
             FROM solicitacao_status_history h
             WHERE h.solicitacao_id = s.id
           ) AS status_history
         FROM solicitacoes s
         JOIN usuarios u ON u.id = s.usuario_id
         ORDER BY s.id DESC`
      );
    } else {
      // Usuário comum enxerga só as dele
      result = await db.query(
        `SELECT
           s.*,
           u.nome AS usuario_nome,
           u.email AS usuario_email,
           (
             SELECT COUNT(*)::int
             FROM solicitacao_arquivos a
             WHERE a.solicitacao_id = s.id
           ) AS "docsExtrasCount",
           (
             SELECT COALESCE(
               json_agg(
                 json_build_object(
                   'status', h.status,
                   'date', h.data_movimentacao,
                   'origem', COALESCE(h.origem, 'API'),
                   'obs', COALESCE(h.obs, '')
                 )
                 ORDER BY h.data_movimentacao
               ),
               '[]'::json
             )
             FROM solicitacao_status_history h
             WHERE h.solicitacao_id = s.id
           ) AS status_history
         FROM solicitacoes s
         JOIN usuarios u ON u.id = s.usuario_id
         WHERE s.usuario_id = $1
         ORDER BY s.id DESC`,
        [id]
      );
    }

    return res.json(result.rows);
  } catch (err) {
    console.error('Erro em GET /solicitacoes:', err);
    return res.status(500).json({ error: 'Erro ao listar solicitações.' });
  }
});

// Criar nova solicitação
app.post('/solicitacoes', authMiddleware, async (req, res) => {
  try {
    const { id: usuarioId } = req.user;
    const {
      solicitante_nome,
      beneficiario_nome,
      beneficiario_doc,
      numero_nf,
      data_nf,
      valor_nf,
      emitente_nome,
      emitente_doc,
      status,
      protocolo,
      nr_protocolo,
      numero_protocolo,
      valor,
      valor_solicitado,
      data_solicitacao,
      data,
      descricao,            // 🔹 descrição no body
    } = req.body;

    const protocoloFinal =
      protocolo || nr_protocolo || numero_protocolo || null;

    const dataSolicFinal = data_solicitacao || data || null;

    const valorSolicFinal =
      valor_solicitado ?? valor ?? null;

    const insertResult = await db.query(
      `INSERT INTO solicitacoes (
        usuario_id,
        solicitante_nome,
        beneficiario_nome,
        beneficiario_doc,
        numero_nf,
        data_nf,
        valor_nf,
        emitente_nome,
        emitente_doc,
        status,
        protocolo,
        data_solicitacao,
        valor,
        descricao          -- 🔹 coluna nova
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
      RETURNING *`,
      [
        usuarioId,
        solicitante_nome || null,
        beneficiario_nome || null,
        beneficiario_doc || null,
        numero_nf || null,
        data_nf || null,
        valor_nf || valorSolicFinal || null,
        emitente_nome || null,
        emitente_doc || null,
        status || 'Em análise',
        protocoloFinal,
        dataSolicFinal,
        valorSolicFinal,
        descricao || null
      ]
    );

    const created = insertResult.rows[0];

    // 🔹 Histórico inicial de status
    try {
      const statusInicial = created.status || 'Em análise';
      const dataInicial =
        created.data_solicitacao ||
        created.data_nf ||
        new Date();

      await db.query(
        `INSERT INTO solicitacao_status_history (
          solicitacao_id,
          status,
          data_movimentacao,
          origem,
          obs
        ) VALUES ($1,$2,$3,$4,$5)`,
        [created.id, statusInicial, dataInicial, 'Criação', 'Status inicial']
      );
    } catch (errHist) {
      console.error('Erro ao inserir histórico inicial de status:', errHist);
    }

    return res.status(201).json(created);
  } catch (err) {
    console.error('Erro em POST /solicitacoes:', err);
    return res.status(500).json({ error: 'Erro ao criar solicitação.' });
  }
});

// Atualizar solicitação
app.put('/solicitacoes/:id', authMiddleware, async (req, res) => {
  try {
    const solId = parseInt(req.params.id, 10);

    if (Number.isNaN(solId)) {
      return res.status(400).json({ error: 'ID inválido.' });
    }

    const { id: usuarioId, tipo } = req.user;

    // 1) Buscar a solicitação atual (respeitando admin / user)
    let query = 'SELECT * FROM solicitacoes WHERE id = $1';
    const params = [solId];

    if (tipo !== 'admin') {
      query += ' AND usuario_id = $2';
      params.push(usuarioId);
    }

    const existingResult = await db.query(query, params);
    if (existingResult.rows.length === 0) {
      return res
        .status(404)
        .json({ error: 'Solicitação não encontrada para este usuário.' });
    }

    const existing = existingResult.rows[0];

    const {
      status,
      protocolo,
      nr_protocolo,
      numero_protocolo,
      data_solicitacao,
      data,
      valor,
      valor_solicitado,
      descricao,    // 🔹 descrição
      statusDate,   // 🔹 data da movimentação (vem do front)
    } = req.body;

    const protocoloFinal =
      protocolo || nr_protocolo || numero_protocolo || existing.protocolo || null;

    const dataSolicFinal =
      data_solicitacao ||
      data ||
      existing.data_solicitacao ||
      existing.data_nf ||
      null;

    const valorFinal =
      valor_solicitado ??
      valor ??
      existing.valor ??
      existing.valor_nf ??
      null;

    const descricaoFinal =
      descricao ?? existing.descricao ?? null;

    const statusFinal =
      status || existing.status || null;

    // 🔹 Data da última mudança: se veio uma data explícita, usamos; senão mantemos
    let dataUltimaMudancaFinal =
      existing.data_ultima_mudanca ||
      existing.data_solicitacao ||
      existing.data_nf ||
      null;

    if (status && statusDate) {
      dataUltimaMudancaFinal = statusDate;
    }

    const updateResult = await db.query(
      `UPDATE solicitacoes
       SET
         status              = COALESCE($1, status),
         protocolo           = COALESCE($2, protocolo),
         data_solicitacao    = COALESCE($3, data_solicitacao),
         valor               = COALESCE($4, valor),
         descricao           = COALESCE($5, descricao),
         data_ultima_mudanca = COALESCE($6, data_ultima_mudanca)
       WHERE id = $7
       RETURNING *`,
      [
        statusFinal,
        protocoloFinal,
        dataSolicFinal,
        valorFinal,
        descricaoFinal,
        dataUltimaMudancaFinal,
        solId,
      ]
    );

    const updated = updateResult.rows[0];

    // 2) Registrar a movimentação no histórico (sem travar nada se der erro)
    if (status && statusDate) {
      try {
        await db.query(
          `INSERT INTO solicitacao_status_history (
            solicitacao_id,
            status,
            data_movimentacao,
            origem,
            obs
          ) VALUES ($1,$2,$3,$4,$5)`,
          [
            solId,
            status,
            statusDate,
            'API',
            'Movimentação de status via aplicação',
          ]
        );
      } catch (errHist) {
        console.error('Erro ao inserir histórico de status:', errHist);
      }
    }

    return res.json(updated);
  } catch (err) {
    console.error('Erro em PUT /solicitacoes/:id:', err);
    return res.status(500).json({ error: 'Erro ao atualizar solicitação.' });
  }
});
