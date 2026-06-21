"""Idempotent Kibana setup: index pattern + 5 Lens visualizations + 1 dashboard.

Creates everything needed to view PhishGuard verdicts in Kibana 8.x. Re-runnable.
"""
import argparse
import json
import os
import sys
from typing import Any

try:
    import httpx
except ImportError:
    print("Missing httpx. Run: pip install httpx")
    sys.exit(2)

INDEX_PATTERN_ID = "phishguard-verdicts"
INDEX_PATTERN_TITLE = "phishguard-verdicts-*"
TIME_FIELD = "@timestamp"
DASHBOARD_ID = "phishguard-ops"
DASHBOARD_TITLE = "PhishGuard Operations"

KBN_HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}
def kbn_request(client, method, path, body=None):
    resp = client.request(method, path, headers=KBN_HEADERS, json=body)
    return resp


def upsert_object(client, obj_type, obj_id, attributes, references=None, overwrite=True):
    """Create-or-update a saved object via Kibana saved-objects API."""
    body = {"attributes": attributes}
    if references:
        body["references"] = references
    qs = "?overwrite=true" if overwrite else ""
    path = "/api/saved_objects/" + obj_type + "/" + obj_id + qs
    r = kbn_request(client, "POST", path, body)
    if r.status_code in (200, 201):
        return r.json()
    if r.status_code == 409 and not overwrite:
        path = "/api/saved_objects/" + obj_type + "/" + obj_id
        return kbn_request(client, "PUT", path, body).json()
    raise RuntimeError("Kibana " + str(r.status_code) + " on " + obj_type + "/" + obj_id + ": " + r.text[:300])


def index_pattern_attrs():
    return {
        "title": INDEX_PATTERN_TITLE,
        "timeFieldName": TIME_FIELD,
    }
def _index_ref(layer_id="layer1"):
    return [{
        "name": "indexpattern-datasource-layer-" + layer_id,
        "type": "index-pattern",
        "id": INDEX_PATTERN_ID,
    }]


def _terms_col(field, size=10, order_by="count_col", order_dir="desc"):
    return {
        "dataType": "string",
        "isBucketed": True,
        "label": "Top values of " + field,
        "operationType": "terms",
        "scale": "ordinal",
        "sourceField": field,
        "params": {
            "size": size,
            "orderBy": {"type": "column", "columnId": order_by},
            "orderDirection": order_dir,
            "otherBucket": False,
            "missingBucket": False,
        },
    }


def _count_col(label="Count"):
    return {
        "dataType": "number",
        "isBucketed": False,
        "label": label,
        "operationType": "count",
        "scale": "ratio",
        "sourceField": "___records___",
    }


def _date_histogram_col(field=TIME_FIELD):
    return {
        "dataType": "date",
        "isBucketed": True,
        "label": field,
        "operationType": "date_histogram",
        "scale": "interval",
        "sourceField": field,
        "params": {"interval": "auto", "includeEmptyRows": True, "dropPartials": False},
    }


def _range_col(field, ranges):
    """Bucket numeric field into ranges, for ML score distribution."""
    return {
        "dataType": "number",
        "isBucketed": True,
        "label": field,
        "operationType": "range",
        "scale": "interval",
        "sourceField": field,
        "params": {"type": "range", "ranges": ranges, "maxBars": 8},
    }
def es_index_template():
    return {
        "index_patterns": [INDEX_PATTERN_TITLE],
        "priority": 200,
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "email_id": {"type": "keyword"},
                    "verdict": {"type": "keyword"},
                    "confidence": {"type": "float"},
                    "sender": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                    "sender_domain": {"type": "keyword"},
                    "sender_ip": {"type": "ip"},
                    "subject": {"type": "text"},
                    "url_count": {"type": "integer"},
                    "attachment_count": {"type": "integer"},
                    "l1_verdict": {"type": "keyword"},
                    "l2_verdict": {"type": "keyword"},
                    "l2_confidence": {"type": "float"},
                    "l2_engine_scores": {"properties": {
                        "structural": {"type": "float"},
                        "nlp": {"type": "float"},
                        "behavioral": {"type": "float"},
                    }},
                    "l3_verdict": {"type": "keyword"},
                    "l3_score": {"type": "float"},
                    "l3_final_url": {"type": "keyword"},
                    "ml_score": {"type": "float"},
                    "ml_label": {"type": "keyword"},
                    "ml_available": {"type": "boolean"},
                }
            }
        }
    }

def viz_verdict_donut():
    layer_id = "layer1"
    bucket_id = "bucket"
    metric_id = "metric"
    return {
        "title": "Verdict distribution",
        "visualizationType": "lnsPie",
        "state": {
            "datasourceStates": {"formBased": {"layers": {layer_id: {
                "columnOrder": [bucket_id, metric_id],
                "columns": {
                    bucket_id: _terms_col("verdict", size=5, order_by=metric_id),
                    metric_id: _count_col("Verdict count"),
                },
                "incompleteColumns": {},
            }}}},
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "shape": "donut",
                "layers": [{
                    "layerId": layer_id,
                    "primaryGroups": [bucket_id],
                    "metrics": [metric_id],
                    "categoryDisplay": "default",
                    "legendDisplay": "default",
                    "numberDisplay": "percent",
                    "layerType": "data",
                }],
            },
        },
        "references": _index_ref(layer_id),
    }


def viz_verdicts_over_time():
    layer_id = "layer1"
    time_id = "time"
    split_id = "split"
    metric_id = "metric"
    return {
        "title": "Verdicts over time",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {"formBased": {"layers": {layer_id: {
                "columnOrder": [time_id, split_id, metric_id],
                "columns": {
                    time_id: _date_histogram_col(),
                    split_id: _terms_col("verdict", size=3, order_by=metric_id),
                    metric_id: _count_col(),
                },
                "incompleteColumns": {},
            }}}},
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "axisTitlesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "fittingFunction": "None",
                "gridlinesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
                "layers": [{
                    "accessors": [metric_id],
                    "layerId": layer_id,
                    "layerType": "data",
                    "seriesType": "area_stacked",
                    "splitAccessor": split_id,
                    "xAccessor": time_id,
                }],
                "legend": {"isVisible": True, "position": "right"},
                "preferredSeriesType": "area_stacked",
                "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "valueLabels": "hide",
            },
        },
        "references": _index_ref(layer_id),
    }
def viz_top_sender_domains():
    layer_id = "layer1"
    bucket_id = "bucket"
    metric_id = "metric"
    return {
        "title": "Top sender domains (phishing only)",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {"formBased": {"layers": {layer_id: {
                "columnOrder": [bucket_id, metric_id],
                "columns": {
                    bucket_id: _terms_col("sender_domain", size=10, order_by=metric_id),
                    metric_id: _count_col(),
                },
                "incompleteColumns": {},
            }}}},
            "filters": [],
            "query": {"language": "kuery", "query": "verdict : phishing or verdict : suspicious"},
            "visualization": {
                "axisTitlesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "fittingFunction": "None",
                "gridlinesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "labelsOrientation": {"x": -45, "yLeft": 0, "yRight": 0},
                "layers": [{
                    "accessors": [metric_id],
                    "layerId": layer_id,
                    "layerType": "data",
                    "seriesType": "bar_horizontal",
                    "xAccessor": bucket_id,
                }],
                "legend": {"isVisible": False, "position": "right"},
                "preferredSeriesType": "bar_horizontal",
                "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "valueLabels": "show",
            },
        },
        "references": _index_ref(layer_id),
    }


def _score_histogram(title, score_field, viz_id_label):
    layer_id = "layer1"
    bucket_id = "bucket"
    metric_id = "metric"
    ranges = [
        {"from": 0.0, "to": 0.2, "label": "0.0-0.2"},
        {"from": 0.2, "to": 0.4, "label": "0.2-0.4"},
        {"from": 0.4, "to": 0.6, "label": "0.4-0.6"},
        {"from": 0.6, "to": 0.8, "label": "0.6-0.8"},
        {"from": 0.8, "to": 1.01, "label": "0.8-1.0"},
    ]
    return {
        "title": title,
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {"formBased": {"layers": {layer_id: {
                "columnOrder": [bucket_id, metric_id],
                "columns": {
                    bucket_id: _range_col(score_field, ranges),
                    metric_id: _count_col(),
                },
                "incompleteColumns": {},
            }}}},
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "axisTitlesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "fittingFunction": "None",
                "gridlinesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
                "layers": [{
                    "accessors": [metric_id],
                    "layerId": layer_id,
                    "layerType": "data",
                    "seriesType": "bar",
                    "xAccessor": bucket_id,
                }],
                "legend": {"isVisible": False, "position": "right"},
                "preferredSeriesType": "bar",
                "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "valueLabels": "show",
            },
        },
        "references": _index_ref(layer_id),
    }


def viz_ml_score_histogram():
    return _score_histogram("ML score distribution", "ml_score", "ml-hist")


def viz_l2_confidence_histogram():
    return _score_histogram("Layer 2 confidence distribution", "l2_confidence", "l2-hist")
def build_dashboard_panels():
    panels, layout = [], [(0,0,16,12),(16,0,32,12),(0,12,24,14),(24,12,12,14),(36,12,12,14)]
    for slot in range(len(layout)):
        x, y, w, h = layout[slot]
        panels.append({
            "embeddableConfig": {"enhancements": {}},
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(slot)},
            "panelIndex": str(slot),
            "panelRefName": "panel_" + str(slot),
            "type": "lens",
            "version": "8.13.2",
        })
    return panels

def dashboard_attrs():
    pp = build_dashboard_panels()
    out = dict()
    out["title"] = DASHBOARD_TITLE
    out["description"] = "PhishGuard live verdict feed"
    out["panelsJSON"] = json.dumps(pp)
    out["optionsJSON"] = json.dumps({"hidePanelTitles": False, "useMargins": True})
    out["version"] = 1
    out["timeRestore"] = False
    ssj = json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
    out["kibanaSavedObjectMeta"] = {"searchSourceJSON": ssj}
    return out


def dashboard_references(viz_ids):
    refs = []
    for slot in range(len(viz_ids)):
        refs.append({"name": "panel_" + str(slot), "type": "lens", "id": viz_ids[slot]})
    return refs
def setup_es(es_url, auth, reset_indexes=False):
    import httpx
    with httpx.Client(base_url=es_url, auth=auth, timeout=30, verify=False) as ec:
        print("  - es index template...")
        r = ec.put("/_index_template/phishguard-verdicts", json=es_index_template())
        if r.status_code >= 400:
            print("    template push failed: " + str(r.status_code) + " " + r.text[:200])
        else:
            print("    template phishguard-verdicts ok")
        if reset_indexes:
            print("  - dropping existing indexes...")
            r = ec.get("/_cat/indices/" + INDEX_PATTERN_TITLE + "?format=json")
            if r.status_code == 200:
                names = [item["index"] for item in r.json()]
                for nm in names:
                    rd = ec.delete("/" + nm)
                    print("    " + nm + " -> " + str(rd.status_code))
                if not names:
                    print("    (no existing indexes)")
            else:
                print("    list failed: " + str(r.status_code))


def setup(client):
    print("  - index pattern...")
    upsert_object(client, "index-pattern", INDEX_PATTERN_ID, index_pattern_attrs())

    viz_specs = [
        ("phishguard-verdict-donut", viz_verdict_donut),
        ("phishguard-verdicts-time", viz_verdicts_over_time),
        ("phishguard-top-senders", viz_top_sender_domains),
        ("phishguard-ml-hist", viz_ml_score_histogram),
        ("phishguard-l2-conf-hist", viz_l2_confidence_histogram),
    ]
    viz_ids = []
    for vid, builder in viz_specs:
        spec = builder()
        attrs = dict(title=spec["title"], visualizationType=spec["visualizationType"], state=spec["state"])
        refs = spec["references"]
        print("  - lens viz: " + spec["title"])
        upsert_object(client, "lens", vid, attrs, references=refs)
        viz_ids.append(vid)

    print("  - dashboard...")
    upsert_object(client, "dashboard", DASHBOARD_ID, dashboard_attrs(), references=dashboard_references(viz_ids))

def main():
    ap = argparse.ArgumentParser(description="Idempotent Kibana dashboard setup for PhishGuard.")
    ap.add_argument("--kibana-url", default=os.environ.get("KIBANA_URL", "http://localhost:5601"))
    ap.add_argument("--username", default=os.environ.get("KIBANA_USERNAME", "elastic"))
    ap.add_argument("--password", default=os.environ.get("KIBANA_PASSWORD", "changeme"))
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--es-url", default=os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200"))
    ap.add_argument("--es-username", default=os.environ.get("ELASTICSEARCH_USERNAME", "elastic"))
    ap.add_argument("--es-password", default=os.environ.get("ELASTICSEARCH_PASSWORD", "changeme"))
    ap.add_argument("--reset-indexes", action="store_true", help="Drop existing phishguard-verdicts-* indexes before re-creating")
    args = ap.parse_args()

    print("Kibana setup at " + args.kibana_url)
    auth = (args.username, args.password)
    with httpx.Client(base_url=args.kibana_url, auth=auth, verify=not args.insecure, timeout=30) as client:
        r = client.get("/api/status")
        if r.status_code >= 400:
            print("Kibana status check failed: " + str(r.status_code) + " " + r.text[:200])
            return 1
        try:
            v = r.json().get("version", {}).get("number", "?")
        except Exception:
            v = "?"
        print("Connected to Kibana " + v)
        try:
            setup_es(args.es_url, (args.es_username, args.es_password), reset_indexes=args.reset_indexes)
            setup(client)
        except Exception as exc:
            print("Setup failed: " + str(exc))
            return 2
    print("")
    print("Done. Open: " + args.kibana_url + "/app/dashboards#/view/" + DASHBOARD_ID)
    return 0


if __name__ == "__main__":
    sys.exit(main())
