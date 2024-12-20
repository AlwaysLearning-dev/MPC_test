import os
import json
from qdrant_client import QdrantClient
from datetime import date
from tqdm import tqdm
import uuid

from sentence_transformers import SentenceTransformer

def load_sigma_rules(directory):
    """Recursively load all Sigma rule YAML files from the specified directory."""
    import yaml
    sigma_rules = []
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith(".yml") or filename.endswith(".yaml"):
                filepath = os.path.join(root, filename)
                with open(filepath, 'r', encoding='utf-8') as f:
                    try:
                        documents = list(yaml.safe_load_all(f))
                        for doc in documents:
                            if doc:
                                doc["filename"] = os.path.relpath(filepath, directory)
                                sigma_rules.append(doc)
                    except yaml.YAMLError as e:
                        print(f"Error parsing {filepath}: {e}")
    return sigma_rules

def prepare_payload(sigma_rule):
    """Prepare the payload metadata for a Sigma rule."""
    def serialize(obj):
        if isinstance(obj, date):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")

    return json.loads(json.dumps({
        "title": sigma_rule.get("title"),
        "id": sigma_rule.get("id"),
        "status": sigma_rule.get("status"),
        "description": sigma_rule.get("description"),
        "references": sigma_rule.get("references"),
        "author": sigma_rule.get("author"),
        "date": sigma_rule.get("date"),
        "modified": sigma_rule.get("modified"),
        "tags": sigma_rule.get("tags"),
        "logsource": sigma_rule.get("logsource"),
        "detection": sigma_rule.get("detection"),
        "falsepositives": sigma_rule.get("falsepositives"),
        "level": sigma_rule.get("level"),
        "filename": sigma_rule.get("filename")
    }, default=serialize))

def ingest_with_sentence_transformers(client, collection_name, sigma_rules):
    """Embed Sigma rules using SentenceTransformers and ingest them into Qdrant."""
    # Load pre-trained embedding model
    model = SentenceTransformer('all-MiniLM-L6-v2')  # 384-dim embeddings

    # Detect embedding size
    test_embedding = model.encode(["Dimension test"])[0]
    dimension = len(test_embedding)
    print(f"Detected embedding size from SentenceTransformers: {dimension}")

    # Recreate Qdrant collection
    client.recreate_collection(
        collection_name=collection_name,
        vectors_config={
            "default": {
                "size": dimension,  # Matches SentenceTransformers embeddings
                "distance": "Cosine"
            }
        }
    )

    points = []
    batch_size = 100
    sigma_texts = []

    # Collect Sigma rules as text
    for rule in sigma_rules:
        sigma_texts.append(json.dumps(rule, indent=2, default=str))

    # Embed in batches
    for i in tqdm(range(0, len(sigma_texts), batch_size), desc="Embedding in batches"):
        batch_texts = sigma_texts[i:i + batch_size]
        batch_embeddings = model.encode(batch_texts)

        for j, embedding in enumerate(batch_embeddings):
            rule_idx = i + j
            payload = prepare_payload(sigma_rules[rule_idx])
            points.append({
                "id": str(uuid.uuid4()),
                "vector": {"default": embedding.tolist()},
                "payload": payload
            })

    # Upsert into Qdrant in batches
    for k in tqdm(range(0, len(points), batch_size), desc="Uploading to Qdrant"):
        client.upsert(collection_name=collection_name, points=points[k:k+batch_size])

if __name__ == "__main__":
    sigma_directory = "<ADD>"
    collection_name = "sigma_rules"
    qdrant_url = "http://localhost:6333"

    sigma_rules = load_sigma_rules(sigma_directory)
    if not sigma_rules:
        print("No Sigma rules found. Exiting.")
        exit(1)

    client = QdrantClient(url=qdrant_url)
    ingest_with_sentence_transformers(client, collection_name, sigma_rules)
    print("Sigma rules ingested into Qdrant with SentenceTransformers embeddings.")
