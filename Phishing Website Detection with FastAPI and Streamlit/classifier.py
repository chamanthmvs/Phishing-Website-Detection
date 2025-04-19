import pandas as pd
import random
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, accuracy_score


# Data Loading
legit_df = pd.read_csv("legitimate-urls.csv")
phish_df = pd.read_csv("phishing-urls.csv")

# Merge both datasets
df = pd.concat([legit_df, phish_df], ignore_index=True)


# Preprocessing
# Drop unnecessary columns by index (0, 3, 5)
df.drop(df.columns[[0, 3, 5]], axis=1, inplace=True)

# Shuffle the dataset
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# Separate features and labels
X = df.drop('label', axis=1)
y = df['label']


# Train-Test Split
random.seed(100)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=100
)

print(f"Train size: {len(X_train)} | Test size: {len(X_test)}")
print("Label distribution in training set:\n", y_train.value_counts())
print("Label distribution in test set:\n", y_test.value_counts())


# Decision Tree Model
dt_model = DecisionTreeClassifier(random_state=0)
dt_model.fit(X_train, y_train)
dt_preds = dt_model.predict(X_test)

print("\nDecision Tree Results:")
print("Confusion Matrix:\n", confusion_matrix(y_test, dt_preds))
print("Accuracy:", accuracy_score(y_test, dt_preds))


# Random Forest Model
rf_model = RandomForestClassifier()
rf_model.fit(X_train, y_train)
rf_preds = rf_model.predict(X_test)

print("\nRandom Forest Results:")
print("Confusion Matrix:\n", confusion_matrix(y_test, rf_preds))
print("Accuracy:", accuracy_score(y_test, rf_preds))


# Improved Random Forest
tuned_rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=30,
    max_leaf_nodes=10000,
    random_state=42
)
tuned_rf.fit(X_train, y_train)
tuned_preds = tuned_rf.predict(X_test)

print("\nTuned Random Forest Results:")
print("Confusion Matrix:\n", confusion_matrix(y_test, tuned_preds))
print("Accuracy:", accuracy_score(y_test, tuned_preds))


#  Save Model
import pickle
with open("random_forest_model.sav", "wb") as f:
     pickle.dump(tuned_rf, f)
