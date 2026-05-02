import json, sys, os, time
from elasticsearch import Elasticsearch, helpers

INPUT_FILE = "data/normalized_indicators.json"
ES_HOST    = "http://localhost:9200"
ES_INDEX   = "threat-indicators"

INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "value":      {"type": "keyword"},
            "type":       {"type": "keyword"},
            "source":     {"type": "keyword"},
            "risk_score": {"type": "integer"},
            "severity":   {"type": "keyword"},
            "tags":       {"type": "keyword"},
            "description":{"type": "text"},
            "country":    {"type": "keyword"},
            "first_seen": {"type": "date"},
            "last_seen":  {"type": "date"},
            "blocked":    {"type": "boolean"},
        }
    }
}

def wait_for_es(es, retries=20):
    print("  Waiting for Elasticsearch", end="", flush=True)
    for i in range(retries):
        try:
            if es.ping():
                print(" Connected!\n")
                return True
        except: pass
        print(".", end="", flush=True)
        time.sleep(5)
    print("\n\n  Could not connect. Run: sudo docker compose up -d")
    return False

def create_index(es):
    if es.indices.exists(index=ES_INDEX):
        print(f"  Index '{ES_INDEX}' already exists")
    else:
        es.indices.create(index=ES_INDEX, body=INDEX_MAPPING)
        print(f"  Created index '{ES_INDEX}'")

def push_data(es, indicators):
    actions = [{"_index":ES_INDEX,"_id":ind["id"],"_source":ind} for ind in indicators]
    success, errors = helpers.bulk(es, actions, raise_on_error=False)
    return success

if __name__ == "__main__":
    print("\n" + "="*50)
    print("  WEEK 2 - STEP 2: ELK Pusher")
    print("="*50)
    if not os.path.exists(INPUT_FILE):
        print(f"\n  File not found: {INPUT_FILE}")
        print("  Run normalizer.py first!")
        sys.exit(1)
    with open(INPUT_FILE) as f:
        indicators = json.load(f)
    print(f"\n  Loaded {len(indicators)} normalized indicators")
    es = Elasticsearch(ES_HOST)
    if not wait_for_es(es): sys.exit(1)
    create_index(es)
    print(f"  Pushing {len(indicators)} indicators...")
    count = push_data(es, indicators)
    print(f"\n  Successfully pushed: {count} documents")
    print("\n" + "="*50)
    print("  Week 2 Complete! Open Kibana:")
    print("  http://localhost:5601")
    print("\n  In Kibana:")
    print("  1. Explore on my own")
    print("  2. Management > Stack Management")
    print("  3. Data Views > Create data view")
    print("  4. Name: threat-indicators*")
    print("  5. Time field: last_seen")
    print("  6. Click Discover!")
    print("="*50)
