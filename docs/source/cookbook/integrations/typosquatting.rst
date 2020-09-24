=============
Typosquatting
=============

The Aura typosquatting protection requires a dataset file that contains a list of python packages and their popularity (number of downloads) in a JSON file. This file can be obtained by querying the Google Big Query service.

.. note::
    Although Google Big Query is a commercial service, Google provides a free tier of 1TB/month of processed data which is more then enough to obtain the data needed for the typosquatting protection for free.


-----------------------
Manual dataset download
-----------------------

To connect to the Big Query service, you must first install the Big Query command line tool from google-cloud-sdk. Follow the official documentation to install this tool. Alternatively, you can use the online console to run the query and export the JSON results to Google Drive https://console.cloud.google.com/bigquery .

Now run the following query to generate the dataset needed for the typosquatting protection:

::

    SELECT file.project as package_name, count(file.project) as downloads
    FROM `the-psf.pypi.downloads*`
    WHERE
        _TABLE_SUFFIX
        BETWEEN FORMAT_DATE(
          '%Y%m%d', DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY))
        AND FORMAT_DATE('%Y%m%d', CURRENT_DATE())
    GROUP BY package_name
    ORDER BY downloads DESC


-------------------------
Download dataset via Aura
-------------------------

If you have a google python sdk installed and authentication configured for the python client, you can download the dataset automatically via Aura by running `aura fetch-pypi-stats`. To find out if your python Big Query SDK is correctly configured, run `aura info` and check the output if the BigQuery service integration is enabled.
