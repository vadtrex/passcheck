import express from 'express';

const app = express();
const port = Number(process.env.PORT ?? 3000);

app.use(express.json({ limit: '1kb' }));

app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok' });
});

app.post('/v1/password/evaluate', (req, res) => {
  res.json({
    received: Boolean(req.body?.password)
  });
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});