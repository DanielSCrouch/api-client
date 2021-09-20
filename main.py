
import json

from client.client import APIClient

def main() -> None:

  # read in connection data
  with open("./data.json") as file:
    params = json.load(file)
    try:
      connection_params = params["connection_parameters"]
    except KeyError as e:
      raise ValueError(e.__str__() + "not provided in data.json")

  # mock api call
  client = APIClient(connection_params)
  params = {"foo1": "bar1", "foo2": "bar2"}
  response = client.get_value(params)
  print(f'main response from api: {response}')

if __name__ == "__main__":
  main()