DATASET REQUIRED FOR TRAINING

Place a labelled CSV file in this folder, for example:
data/phishing_urls.csv

Required columns by default:
url,label

Example header:
url,label

Labels:
1 or phishing = phishing URL
0 or legitimate = legitimate URL

Do not train using invented/demo labels. Use a reputable, legally usable,
labelled URL dataset. Remove duplicates and check class balance before training.
Keep the dataset source and licence in your project documentation.
