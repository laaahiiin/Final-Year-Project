import joblib
import numpy as np
rf = joblib.load('ids_rf_model.pkl')
sc = joblib.load('scaler.pkl')
found = False
i = 0
while not found and i < 100000:
    x = np.random.uniform(-3, 3, size=(1, 46))
    probs = rf.predict_proba(x)[0]
    p = np.argmax(probs)
    if p != 0 and np.max(probs) > 0.95:
        print('Attack vector:', repr(sc.inverse_transform(x)[0]))
        found = True
    i += 1
if not found:
    print('Not found')
