# 📥 Step 1: Set Up the Project and Load the Dataset
# Importing necessary libraries
import pandas as pd

# Load the dataset
df = pd.read_csv("Login_Dataset.csv")

# Print the first few rows of the dataset
print(df.head())

# Columns:
# - 'Login Hour' - Time of day when the login attempt was made (hour)
# - 'Device Type' - Type of device used for login (e.g., Desktop, Tablet, Mobile)
# - 'Failed Attempts' - Number of failed login attempts before the successful one
# - 'IP Risk Score' - Risk score of the IP address (Low, Medium, High)
# - 'Login Status' - Target variable (Normal or Anomalous)

# Target variable: 'Login Status'

# 🔄 Step 2: Encode Categorical Variables
# Importing LabelEncoder for encoding categorical features
from sklearn.preprocessing import LabelEncoder

# Encoding the categorical columns into numbers
df['Device Type'] = LabelEncoder().fit_transform(df['Device Type'])
df['IP Risk Score'] = LabelEncoder().fit_transform(df['IP Risk Score'])
df['Login Status'] = LabelEncoder().fit_transform(df['Login Status'])

# Explanation: We need to encode text into numbers because scikit-learn models require numeric input.
# Models cannot directly handle string data, so we convert categorical variables to numeric using LabelEncoder.

# 📊 Step 3: Prepare Features and Target
# Define the input features (X) and the target variable (y)
X = df[['Login Hour', 'Device Type', 'Failed Attempts', 'IP Risk Score']]
y = df['Login Status']

# 🔀 Step 4: Split into Training and Testing Sets
# Importing the train_test_split function
from sklearn.model_selection import train_test_split

# Split the dataset into training and testing sets (80% training, 20% testing)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Explanation: Splitting the data ensures that the model is evaluated on unseen data, preventing overfitting.
# If we don't split the data, we risk the model performing well on training data but poorly on real-world data.

# 🌳 Step 5: Train the Decision Tree Classifier
# Importing the DecisionTreeClassifier
from sklearn.tree import DecisionTreeClassifier

# Initialize the Decision Tree Classifier with max_depth=3 to avoid overfitting and keep the model simple
clf = DecisionTreeClassifier(max_depth=3, random_state=42)

# Train the classifier on the training data
clf.fit(X_train, y_train)

# Explanation: max_depth=3 limits the depth of the tree to 3 levels. This prevents overfitting and keeps the model interpretable.

# 🔎 Step 6: Make Predictions and Evaluate
# Importing the necessary evaluation metrics
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Predict the labels for the test set
y_pred = clf.predict(X_test)

# Print the evaluation metrics
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred))
print("Recall:", recall_score(y_test, y_pred))
print("F1 Score:", f1_score(y_test, y_pred))

# Print the confusion matrix
from sklearn.metrics import confusion_matrix
print(confusion_matrix(y_test, y_pred))

# These metrics give us insight into the classifier's performance:
# - Accuracy: Overall correctness of the model
# - Precision: The proportion of positive predictions that were actually correct
# - Recall: The proportion of actual positives that were correctly identified
# - F1 Score: Harmonic mean of Precision and Recall
# - Confusion Matrix: Shows true positives, false positives, true negatives, and false negatives
