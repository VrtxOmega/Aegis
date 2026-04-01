from flask import Blueprint, jsonify
import requests

weather_bp = Blueprint('weather', __name__)

# WMO Weather Code to description mapping
WMO_CODES = {
    0: 'Clear sky', 1: 'Mainly clear', 2: 'Partly cloudy', 3: 'Overcast',
    45: 'Foggy', 48: 'Depositing rime fog',
    51: 'Light drizzle', 53: 'Moderate drizzle', 55: 'Dense drizzle',
    61: 'Slight rain', 63: 'Moderate rain', 65: 'Heavy rain',
    66: 'Light freezing rain', 67: 'Heavy freezing rain',
    71: 'Slight snow', 73: 'Moderate snow', 75: 'Heavy snow',
    77: 'Snow grains', 80: 'Slight rain showers', 81: 'Moderate rain showers',
    82: 'Violent rain showers', 85: 'Slight snow showers', 86: 'Heavy snow showers',
    95: 'Thunderstorm', 96: 'Thunderstorm with slight hail',
    99: 'Thunderstorm with heavy hail'
}

# Bethalto, IL coordinates
LATITUDE = 38.91
LONGITUDE = -90.04
LOCATION_NAME = 'Bethalto, IL'


@weather_bp.route('/')
def get_weather():
    """Fetch weather from Open-Meteo (primary) with wttr.in fallback."""
    # Try Open-Meteo first (free, no API key, highly reliable)
    try:
        url = (
            f'https://api.open-meteo.com/v1/forecast'
            f'?latitude={LATITUDE}&longitude={LONGITUDE}'
            f'&current=temperature_2m,relative_humidity_2m,apparent_temperature,weather_code,wind_speed_10m'
            f'&temperature_unit=fahrenheit&wind_speed_unit=mph'
        )
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        current = data['current']
        weather_code = current.get('weather_code', 0)

        return jsonify({
            'location': LOCATION_NAME,
            'temperature_f': str(round(current['temperature_2m'])),
            'description': WMO_CODES.get(weather_code, f'Code {weather_code}'),
            'wind_mph': str(round(current['wind_speed_10m'])),
            'humidity': str(current['relative_humidity_2m']),
            'feels_like_f': str(round(current['apparent_temperature'])),
            'source': 'open-meteo'
        })
    except Exception as e_primary:
        pass

    # Fallback: wttr.in
    try:
        url = f'https://wttr.in/{LOCATION_NAME.replace(", ", "+")}?format=j1&lang=en&u'
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data is None:
            raise ValueError('wttr.in returned null response')
        current_condition = data['current_condition'][0]
        return jsonify({
            'location': data['nearest_area'][0]['areaName'][0]['value'] + ', ' + data['nearest_area'][0]['region'][0]['value'],
            'temperature_f': current_condition['temp_F'],
            'description': current_condition['weatherDesc'][0]['value'],
            'wind_mph': current_condition['windspeedMiles'],
            'humidity': current_condition['humidity'],
            'feels_like_f': current_condition['FeelsLikeF'],
            'source': 'wttr.in'
        })
    except Exception as e_fallback:
        return jsonify({
            'error': f'All weather sources failed. Primary: {str(e_primary)}, Fallback: {str(e_fallback)}'
        }), 503
