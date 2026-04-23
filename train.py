import os, pickle
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
import tensorflow as tf
import warnings
warnings.filterwarnings("ignore")
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.makedirs("models", exist_ok=True)

N = 60000
np.random.seed(42)

normal = np.column_stack([
    np.random.choice([6,17], N),
    np.random.normal(500,200,N).clip(40,1500),
    np.random.randint(1024,65535,N),
    np.random.choice([80,443,53,22],N),
    np.random.choice([2,16,24,18],N),
    np.random.exponential(0.05,N).clip(0.001,2.0)
])
y_normal = np.zeros(N)

attack = np.column_stack([
    np.random.choice([6,17], N),
    np.random.normal(64,10,N).clip(40,100),
    np.random.randint(1024,65535,N),
    np.random.choice([80,443],N),
    np.full(N,2),
    np.random.exponential(0.0001,N).clip(0.00001,0.001)
])
y_attack = np.ones(N)

X = np.vstack([normal, attack]).astype(np.float32)
y = np.concatenate([y_normal, y_attack]).astype(int)

idx = np.random.permutation(len(X))
X, y = X[idx], y[idx]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s  = scaler.transform(X_test)

with open("models/scaler.pkl","wb") as f:
    pickle.dump(scaler, f)
print("Scaler features:", scaler.n_features_in_)

model = tf.keras.Sequential([
    tf.keras.layers.Input(shape=(6,)),
    tf.keras.layers.Dense(64, activation="relu"),
    tf.keras.layers.Dropout(0.3),
    tf.keras.layers.Dense(32, activation="relu"),
    tf.keras.layers.Dense(1,  activation="sigmoid")
])
model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
model.fit(X_train_s, y_train, epochs=20, batch_size=512,
          validation_split=0.2, verbose=1)
model.save("models/model.h5")

y_pred = (model.predict(X_test_s, verbose=0) > 0.5).astype(int).flatten()
print("ACCURACY:", round(accuracy_score(y_test, y_pred)*100, 2), "%")
cm = confusion_matrix(y_test, y_pred)
print("TN:", cm[0][0], "FP:", cm[0][1])
print("FN:", cm[1][0], "TP:", cm[1][1])
print("DONE - 6 features saved")