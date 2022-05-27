# Prometheus JSON remote write proxy

## Background

[Prometheus Remote Write API](https://prometheus.io/docs/prometheus/latest/querying/api/#remote-write-receiver) accepts remote-write requests encoded in Protobuf format. 
Some environments may have troubles encoding Protobuf requests, like IOT devices running micropython code with very little RAM available. It's sometimes just easier to build a JSON payload.

This proxy receives JSON-encoded [`prompb.RemoteWrite` requests] on the `/write` path and forwards them to the configured `-remote-write-address` address encoded as Protobufs.

### Example JSON payload

```json
{
  "timeseries": [
    {
      "labels": [
        {
          "name": "__name__",
          "value": "test_metric1"
        },
        {
          "name": "b",
          "value": "c"
        },
        {
          "name": "baz",
          "value": "qux"
        },
        {
          "name": "d",
          "value": "e"
        },
        {
          "name": "foo",
          "value": "bar"
        }
      ],
      "samples": [
        {
          "value": 1
        }
      ],
      "exemplars": [
        {
          "labels": [
            {
              "name": "f",
              "value": "g"
            }
          ],
          "value": 1
        }
      ]
    }
  ]
}
```
