import numpy as np
import pandas as pd
import json


def build_df(file_json):
    """
    :param file_json:
    :return: df
    """
    with open(file_json, "r", encoding="utf-8") as result_json:
        obj = json.load(result_json)

    lines = []
    # Results:list
    Results = obj["Results"]

    # Result:dict
    for Result in Results:
        Target = Result.get("Target", np.NaN)
        Class = Result.get("Class", np.NaN)
        Type = Result.get("Type", np.NaN)

        # Vulnerabilities:list
        Vulnerabilities = Result.get("Vulnerabilities", [])

        # Vulnerability:dict
        for Vulnerability in Vulnerabilities:
            VulnerabilityID = Vulnerability.get("VulnerabilityID", np.NaN)
            PkgName = Vulnerability.get("PkgName", np.NaN)
            Severity = Vulnerability.get("Severity", np.NaN)
            line = {
                "Target": Target,
                "Class": Class,
                "Type": Type,
                "VulnerabilityID": VulnerabilityID,
                "PkgName": PkgName,
                "Severity": Severity
            }
            lines.append(line)
    df = pd.DataFrame(lines)
    print(df.head(5))

    return df


def severity_stats(df):
    df_result = df[["Target", "PkgName", "Severity", 'VulnerabilityID']] \
        .groupby(["Target", "PkgName", "Severity"]) \
        .size() \
        .reset_index()
    df_result = df_result.rename(columns={0: 'count'})
    return df_result



def main():
    str_file = "./kicbase.json"
    # str_file = "./result_k8s_minikube.json"

    df = build_df(str_file)
    df.to_csv("./{}_df.csv".format(str_file), index=False)
    df_result = severity_stats(df)
    # df_result.to_csv("./{}_result.csv".format(str_file), index=False)
    # -------
    values_target = df['Target'].value_counts().index.tolist()
    dict_target2spname = {target: 'target{}'.format(i) for i, target in enumerate(values_target)}
    df['Target_simple_name'] = df['Target'].apply(lambda x:dict_target2spname[x])








if __name__ == '__main__':
    main()
