def predict(X_pred: dict) -> float:
    import pickle
    import pandas as pd
    from model.features import features  # Import the expected features list

    with open('phishing_model.pkl', 'rb') as file:
        loaded_model = pickle.load(file)
    
    # Ensure we only pass features the model expects, in the correct order
    X = pd.DataFrame([{feat: X_pred.get(feat, 0) for feat in features}])
    
    phis = loaded_model.predict(X)
    return phis
