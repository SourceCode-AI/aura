.. warning::

    This part of a documentation is still a work in progress and may not reflect publicly accessible data


PyPI dataset SQLite schema
==========================

Since Aura version 2.1, we started providing the global pypi dataset also in the SQLite database format.
The following is an ER diagram of tables within the dataset:

.. mermaid::

   erDiagram
     scans ||--o{ detections : contains
     detections }|--|| detection_types : has_type
     detections ||--o{ tags : contains
     tags }|--|| tag_names : has_name
     scans {
       integer id
       varchar package_name
       JSON metadata
     }
     detection_types {
       integer id
       text name
     }
     detections {
       integer id
       integer scan
       integer type
       text signature
       text message
       integer score
       blob extra
     }
     tag_names {
       integer id
       varchar name
     }
     tags {
       integer detection
       integer tag
     }


The script used to convert the JSON line dataset into SQLite format is located inside the main Aura repository under ``files/dataset_scripts/convert2sqlite.py``. We have identified that the `extra` field in the detection that has a free-form depending on a specific detection occupy a large portion of the overall dataset size. For these reason we have decided to compress the data within the `extra` field to reduce the sqlite database size significantly.

The data has been compressed using the following steps:

- serialize the extra JSON (python dictionary) into a string (text)
- compress the serialized string using `zlib.compress`
- store the compressed bytes as blob in the extra column

You can easily deserialize the data to it's original form by using zlib decompress on the bytes and then loading the string via ``json.loads()``.
