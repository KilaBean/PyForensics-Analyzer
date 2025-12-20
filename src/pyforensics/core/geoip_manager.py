import os
import socket

# Try importing geoip2, set flag if available
try:
    import geoip2.database
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False

class GeoIPManager:
    def __init__(self, db_filename="GeoLite2-City.mmdb"):
        self.reader = None
        self.available = False
        
        if not HAS_GEOIP:
            print("Warning: 'geoip2' library not installed. GeoIP features disabled.")
            return

        # Look for the DB file in common locations
        # 1. Current working directory
        # 2. Inside src/pyforensics/data/
        paths_to_check = [
            db_filename,
            os.path.join(os.path.dirname(__file__), "..", "data", db_filename),
            os.path.join("data", db_filename)
        ]

        for path in paths_to_check:
            if os.path.exists(path):
                try:
                    self.reader = geoip2.database.Reader(path)
                    self.available = True
                    print(f"GeoIP Database loaded: {path}")
                    break
                except Exception as e:
                    print(f"Error loading GeoIP DB: {e}")
        
        if not self.available:
            print("Warning: GeoLite2-City.mmdb not found. GeoIP features disabled.")

    def lookup(self, ip_address):
        """
        Returns a dictionary with Country, City, Lat, Lon, ISO.
        Returns None if lookup fails or IP is private.
        """
        if not self.available or not ip_address:
            return None

        # Skip private IPs (192.168.x.x, 10.x.x.x, etc) to save processing
        try:
            if socket.inet_aton(ip_address):
                 # Simple check, robust check requires ipaddress module
                 if ip_address.startswith(("192.168.", "10.", "127.")):
                     return None
        except:
            return None

        try:
            response = self.reader.city(ip_address)
            
            country = response.country.name or "Unknown"
            city = response.city.name or "Unknown"
            iso = response.country.iso_code or ""
            lat = response.location.latitude
            lon = response.location.longitude
            
            return {
                "summary": f"{city}, {country} ({iso})",
                "country": country,
                "city": city,
                "iso": iso,
                "lat": str(lat),
                "lon": str(lon)
            }
        except Exception:
            # IP not found in DB
            return None

    def close(self):
        if self.reader:
            self.reader.close()