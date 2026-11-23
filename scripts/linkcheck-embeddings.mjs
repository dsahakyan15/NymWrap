// Official immutable GGUFs. This catalog does not download or activate a model.
const models={
  nomic:{file:'nomic-embed-text-v1.5.Q4_K_M.gguf',sha256:'d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac',recipe_id:'nomic_v1_5_mean_document_v1',dimension:768},
  'qwen3-0.6b-q8_0':{file:'Qwen3-Embedding-0.6B-Q8_0.gguf',sha256:'06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439',recipe_id:'qwen3_0_6b_last_plain_v1',dimension:1024},
};
for(const model of Object.values(models))Object.freeze(model);
Object.freeze(models);
export function embeddingModel(id){
  if(!Object.hasOwn(models,id))throw Error('unknown_pinned_embedding');
  return models[id];
}
export function knownEmbedding(sha256,recipe_id,dimension){
  return Object.values(models).some(model=>model.sha256===sha256&&model.recipe_id===recipe_id&&model.dimension===dimension);
}
