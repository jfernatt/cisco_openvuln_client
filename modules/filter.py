import pdb
from datetime import datetime

class Filter:

    def __init__(self, base_url, query_params):
        self.base_url = base_url
        self.query_params = query_params
        self.scope = {
            'all' : self.all,
            'by_id' : self.by_id,
            'by_product' : self.by_product,
            'by_software' : self.by_software
        }
        self.nos_types = [
            'asa',
            'fxos',
            'ftd',
            'ios',
            'iosxe',
            'nxos',
            'aci',
            'fmc'
        ]
        self.nos_w_platform_types = [
            'asa',
            'ftd',
            'fxos',
            'nxos'
        ]

    def constrain_by_date(self):
        if self.query_params['params'].get('firstpublished'):
            try:
                startDate = self.query_params['params']['firstpublished'].get('startDate')
                endDate = self.query_params['params']['firstpublished'].get('endDate')
                return f'firstpublished?startDate={startDate}&endDate={endDate}'
            except Exception:
                pdb.set_trace()
                print(
                    f'Dates not parsed in in params: \n  self.query_params\n  firstpublished requires startDate and endDate')
                quit()
        elif self.query_params['params'].get('lastpublished'):
            try:
                startDate = self.query_params['params']['lastpublished'].get('startDate')
                endDate = self.query_params['params']['lastpublished'].get('endDate')
                return f'lastpublished?startDate={startDate}&endDate={endDate}'
            except Exception:
                pdb.set_trace()
                print(
                    f'Dates not parsed in in params: \n  self.query_params\n  firstpublished requires startDate and endDate')
                quit()

    def all(self):
        base_url = self.base_url
        query_string = f'all/'
        if self.query_params.get('params') is None:
            return f'{base_url}{query_string}'
        elif self.query_params['params'].get('severity'):
            query_string = f'severity/{self.query_params["params"].get("severity")}/'
            # severity with first or last published
            if self.query_params['params'].get('firstpublished') or self.query_params['params'].get('lastpublished'):
                query_string += self.constrain_by_date()
            # severity, no other keys
        elif self.query_params['params'].get('firstpublished') or self.query_params['params'].get('lastpublished'):
            query_string += self.constrain_by_date()
        elif self.query_params.get('lastpublished'):
            try:
                return f'severity/{self.query_params["params"].get("severity")}/lastpublished?startDate={startDate}&endDate={endDate}'
            except Exception:
                print(
                    f'Dates not parsed in in params: \n  self.query_params\n  firstpublished requires startDate and endDate')
                quit()
        elif self.query_params['params'].get('year'):
            query_string = f'year/{self.query_params["params"].get("year")}'
        elif self.query_params['params'].get('latest'):
            query_string = f'latest/{self.query_params["params"].get("latest")}'
        return f'{base_url}{query_string}'

    def by_id(self):
        base_url = self.base_url
        if self.query_params['params'].get('advisory'):
            query_string = f'advisory/{self.query_params["params"].get("advisory")}'
        elif self.query_params['params'].get('cve'):
            query_string = f'cve/{self.query_params["params"].get("cve")}'
        elif self.query_params['params'].get('bugid'):
            query_string = f'bugid/{self.query_params["params"].get("bugid")}'
        return f'{base_url}{query_string}'

    def by_product(self):
        base_url = self.base_url
        if self.query_params['params'].get('product_ids'):
            base_url = 'https://sec.cloudapps.cisco.com/security/center/productBoxData.x?prodType=CISCO'
            query_string = f''
        elif self.query_params['params'].get('product'):
            query_string = f'product?/product={self.query_params["params"].get("product")}'
        return f'{base_url}{query_string}'

    def by_software(self):
        base_url = self.base_url
        #Add filter to nos_types
        if self.query_params['params'].get('sw_versions'):
            query_string = f'OS_version/OS_data?OSType={self.query_params["params"].get("sw_versions")}'
        #Add filter to nos_w_platform_types
        elif self.query_params['params'].get('platforms'):
            query_string = f'platforms?OSType={self.query_params["params"].get("platforms")}'
        #NOS
        elif self.query_params['params'].get('nos'):
        #NOS w Platform
            query_string = f'OSType/{self.query_params["params"].get("nos")}?version={self.query_params["params"].get("version")}'
            if self.query_params['params'].get('platform'):
        #NOS w Platform w Advisory
                query_string += f'&platformAlias={self.query_params["params"].get("platform")}'
                if self.query_params['params'].get('advisory'):
                    query_string += f'{self.query_params["params"].get("advisory")}'
        return f'{base_url}{query_string}'

    
    def make_filter(self):
        try:
            scope = self.scope[self.query_params['scope']]
        except Exception:
            # Raise scope not found exception
            print(f'Scope not found in params: \n  self.query_params')
        else:
            return scope()
