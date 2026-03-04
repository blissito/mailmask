# Feature Request: Document/RAG Endpoints para @formmy.app/chat SDK

## Contexto

Estamos usando el SDK de Formmy (`@formmy.app/chat` v0.0.19) para el chat de soporte en [mailmask.studio/docs](https://mailmask.studio/docs). El agente funciona bien para conversación general, pero **no tiene conocimiento específico de nuestra documentación** — necesita poder responder preguntas sobre nuestra API, SDK, configuración DNS, planes, etc. con información precisa.

Actualmente el SDK tiene `agents.update()` con `instructions` y `customInstructions`, que sirve para definir la persona/tono, pero no hay forma de alimentar al agente con documentos de referencia (knowledge base).

## Endpoints solicitados

### 1. `formmy.documents.create(agentId, data)`

Subir un documento/chunk al knowledge base del agente.

```ts
await formmy.documents.create(agentId, {
  content: "# API de Aliases\n\nPOST /api/domains/:id/aliases ...",
  metadata: {
    title: "API Reference - Aliases",
    source: "docs/api/aliases.md",
    category: "api",
  },
});
```

**Campos:**
- `content` (string, required) — texto plano o markdown
- `metadata` (object, optional) — título, fuente, categoría, etc.
- Embedding automático server-side (no queremos manejar vectores del lado del cliente)

### 2. `formmy.documents.list(agentId)`

Listar documentos del knowledge base de un agente.

```ts
const { documents } = await formmy.documents.list(agentId);
// [{ id, title, source, category, createdAt, chunkCount }]
```

### 3. `formmy.documents.delete(agentId, documentId)`

Eliminar un documento del knowledge base.

```ts
await formmy.documents.delete(agentId, docId);
```

### 4. (Nice to have) `formmy.documents.update(agentId, documentId, data)`

Reemplazar contenido de un documento existente (re-embed automático).

## Formato de contenido

- **Texto plano y Markdown** como mínimo
- Chunking automático server-side (nosotros enviamos el documento completo, ustedes lo splitean y embedean)
- Si es posible, soporte para bulk upload (array de documentos en una sola llamada)

## Nuestro caso de uso

Tenemos ~15-20 páginas de docs (API reference, guías de configuración, FAQ, planes/pricing). Queremos:

1. Un script (`scripts/setup-agent.ts`) que suba todos los docs al agente al hacer deploy
2. Que el agente use RAG para responder con información precisa de nuestra documentación
3. Que las respuestas incluyan referencias/links a la doc relevante cuando sea posible

## Autenticación

Asumimos que estos endpoints usan la misma API key (`formmy_pk_live_...`) que el resto del SDK. Si necesitan un secret key separado para operaciones de escritura, está bien — solo necesitamos saber.

## Prioridad

Esto es bloqueante para que nuestro chat de docs sea realmente útil. Sin knowledge base, el agente inventa respuestas o da información genérica. Con la persona configurada (instructions) mejora el tono pero no la precisión.

---

Cualquier duda estamos disponibles. Gracias!
