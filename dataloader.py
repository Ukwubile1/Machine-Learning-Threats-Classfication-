import mlcroissant as mlc
import itertools

# To download the files from Kaggle, the Croissant JSON-LD tool is used.
croissant_dataset = mlc.Dataset('https://www.kaggle.com/datasets/katehighnam/beth-dataset/croissant/download')

# Print out which record sets are available in the dataset...
record_sets = croissant_dataset.metadata.record_sets
print(record_sets)

# The datafiles names for training are stored in a list so we iterate below to download them from Kaggle. A Kaggle API is already created and keys stores elsewhere. 
data_files = ["labelled_testing_data.csv", "labelled_training_data.csv", "labelled_validation_data.csv"]
for file in data_files:
    record_set = croissant_dataset.records(record_set=file)
    print("First 5 records:",
      list(itertools.islice(record_set, 5))
    )
