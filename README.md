# API Observer

API Observer is a browser-based API discovery and documentation tool.

The script passively observes authorized browser activity and can generate:

- API Discovery exports
- Postman collections
- OpenAPI specifications
- Endpoint classifications
- Request and response schemas
- Importance scoring

API Observer is site-agnostic and can operate against any web application using browser fetch/XHR traffic.

## Features

- Automatic endpoint discovery
- Schema inference
- Postman export
- OpenAPI export
- Importance scoring
- Request classification
- Credential redaction
- GUID and identifier normalization
- Multi-site support

## Supported Targets

API Observer has been validated against:

- GitHub
- Microsoft Learn
- eMaint X5

## Privacy

Credential fields are redacted on export.

Other application data may still be present in exports and should be reviewed before sharing.

# Documentation

Detailed documentation is available in the docs folder.

| Topic | Description |
|---------|---------|
| Architecture | docs/architecture.md |
| Classification | docs/classification.md |
| Scoring | docs/scoring.md |
| Privacy | docs/privacy.md |
| Security | SECURITY.md |
| Changelog | CHANGELOG.md |

## License

MIT License
