# Configuration

Configuration controls how AppHub builds and runs your application.

## Build settings

Set the build command and output directory for your application.

- `buildCommand` runs before every deployment
- `outputDirectory` is copied into the runtime image

## Environment variables

Environment variables are available to your build and runtime processes.

```json
{
  "NODE_ENV": "production"
}
```

Back to [Getting Started](getting-started.md) or the [CLI reference](cli-reference.md#flags).
