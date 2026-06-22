def predict(X_pred: dict) -> float:
    import pickle

    with open('phishing_model.pkl', 'rb') as file:
        loaded_model = pickle.load(file)
    

    X = pd.DataFrame([X_pred])
    phis = loaded_model.predict(X)

    return phis
