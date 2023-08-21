import pdb

class Filter:

    def __init__(self, query_params):
        self.name = 'test'
        ALL = self.all
        BY_ID = self.by_id
        BY_PRODUCT = self.by_product
        BY_SOFTWARE = self.by_software
        self.query_params = query_params
        self.scope = {
            'all' : self.all,
            'by_id' : self.by_id,
            'by_product' : self.by_product,
            'by_software' : self.by_software
        }


    #All advisories
        #by first_published
        #by last_published
        #by year
        #by severity rating
        #by impact score and date range
        #last x advisories
    def all(self):

        input = self.query_params
        if self.query_params.get('params') is None:
            return '/all/'
        elif self.query_params['params'].get('severity'):
            # severity with first or last published
            if self.query_params['params'].get('firstpublished'):
                try:
                    startDate = self.query_params['params']['firstpublished'].get('startDate')
                    endDate = self.query_params['params']['firstpublished'].get('endDate')
                    return f'/severity/{self.query_params["params"].get("severity")}/firstpublished?startDate={startDate}&endDate={endDate}'
                except Exception:
                    pdb.set_trace()
                    print(f'Dates not parsed in in params: \n  self.query_params\n  firstpublished requires startDate and endDate')
                    quit()
            elif self.query_params.get('lastpublished'):
                try:
                    return f'/severity/{self.query_params["params"].get("severity")}/lastpublished?startDate={startDate}&endDate={endDate}'
                except Exception:
                    print(f'Dates not parsed in in params: \n  self.query_params\n  firstpublished requires startDate and endDate')
                    quit()
            # severity, no other keys
            else:
                severity = self.query_params['params'].get('severity')
                return f'/all/severity/{severity}'
        '''
        if input.keys()[0] in 'firstpublished':
            #parse start date and end date
            #f'/all/firstpublished?startDate={}&endDate={}'
            1+1
        elif input.keys()[0] in 'lastpublished':
            #f'/all/lastpublished?startDate={}&endDate={}'
            1+1
        elif input.keys()[0] in 'year':
            1+1
            #f'/year/firstpublished?startDate={}&endDate={}'
        if 'latest' in input.keys():
            #latest X advisories
            1+1
        elif input.keys()[0] in 'latest':
            1+1
        '''
        return 'all'

    # By Identifiers
    # by advisory id
    # by CVE id
    # by bug id
    def by_id(self):
        print('by id')

    #By Product
        #by product name combined with security advisory publication
        #by product
    def by_product(self):
        print('by product')

    #By Software
        #All available version of software
        #All available platform names
        #All advisories affecting a version of IOS
        #All advisories affecting a version of asa
        #Targeting a specific platform
        #Specific platform and advisory ID
    def by_software(self):
        print('by software')
    
    def make_filter(self):
        try:
            scope = self.scope[self.query_params['scope']]
        except Exception:
            #Raise scope not found exception
            print(f'Scope not found in params: \n  self.query_params')
        else:
            return scope()