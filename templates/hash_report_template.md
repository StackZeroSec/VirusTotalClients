# Virus Total API Result

**Meaningful Name**: {{ meaningful_name }}

## Threat Classification
{% if label %}
Labels: {{ label }}
{% else %}
No labels found.
{% endif %}

## Reputation

Reputation Score: {{ reputation }}

## Sandbox Verdicts

{% if sandbox_verdicts %}
Verdicts:
{% for verdict, details in sandbox_verdicts.items() %}
- {{ verdict }}
    - Category: {{ details["category"] }}
    - Confidence: {{ details["confidence"]|default("N/D") }}
{% endfor %}
{% else %}
No sandbox verdicts found.
{% endif %}

## Total Votes

Total Votes:
{% for k, v in total_votes.items() %}
- {{ k }}: {{v}}
{% endfor %} 
