import pandas as pd
import joblib
import featureExtraction


feature_names = [
    "UsingIP",
    "LongURL",
    "ShortURL",
    "Symbol@",
    "Redirecting//",
    "PrefixSuffix-",
    "SubDomains",
    "HTTPS",
    "DomainRegLen",
    "Favicon",
    "NonStdPort",
    "HTTPSDomainURL",
    "RequestURL",
    "AnchorURL",
    "LinksInScriptTags",
    "ServerFormHandler",
    "InfoEmail",
    "AbnormalURL",
    "WebsiteForwarding",
    "StatusBarCust",
    "DisableRightClick",
    "UsingPopupWindow",
    "IframeRedirection",
    "AgeofDomain",
    "DNSRecording",
    "WebsiteTraffic",
    "PageRank",
    "GoogleIndex",
    "LinksPointingToPage",
    "StatsReport"
]


model = joblib.load("models/random_forest.pkl")


def predict_url(url):

    features = featureExtraction.extract_features(url)

    data = pd.DataFrame(
        [features],
        columns=feature_names
    )

    prediction = model.predict(data)[0]

    probability = model.predict_proba(data)[0]

    if prediction == 1:
        result = "Legitimate Website"
    else:
        result = "Phishing Website"

    return result, probability, data