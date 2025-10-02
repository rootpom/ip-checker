import requests

def get_ip_info():
    """
    Gets the public IP address and its geographical information.
    """
    # Use a service to get the public IP of the machine
    try:
        ip_response = requests.get('https://api.ipify.org?format=json')
        ip_response.raise_for_status() # Check for HTTP errors
        public_ip = ip_response.json().get('ip')
    except requests.exceptions.RequestException as e:
        print(f"Error fetching public IP: {e}")
        return

    print(f"--- Your Public IP Address: {public_ip} ---")

    # Use ip-api.com to get geographical information
    api_url = f'http://ip-api.com/json/{public_ip}'
    try:
        geo_response = requests.get(api_url)
        geo_response.raise_for_status() # Check for HTTP errors
        data = geo_response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching location data: {e}")
        return

    # Check if the API call was successful
    if data.get('status') == 'success':
        print(f"  Country: {data.get('country')}")
        print(f"  Region:  {data.get('regionName')}")
        print(f"  City:    {data.get('city')}")
        print(f"  ISP:     {data.get('isp')}")
        print(f"  Latitude/Longitude: {data.get('lat')}, {data.get('lon')}")
    else:
        print(f"Could not retrieve IP details. Status: {data.get('message')}")

if __name__ == "__main__":
    get_ip_info()
