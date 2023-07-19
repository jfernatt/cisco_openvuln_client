class Filter():

    def __init__(self, client_args):
        self.name = 'test'
        ALL = self.all
        BY_ID = self.by_id
        BY_PRODUCT = self.by_product
        BY_SOFTWARE = self.by_software
    
    def all(self, input):
        print('all')
        if input in 'all':
            return '/all/'
        elif 'severity' in input.keys():
            #severity, no other keys
            #severity with first or last published
        if input.keys()[0] in 'firstpublished':
            #parse start date and end date
            #f'/all/firstpublished?startDate={}&endDate={}'
        elif input.keys()[0] in 'lastpublished':
            #f'/all/lastpublished?startDate={}&endDate={}'
        else input.keys()[0] in 'year':
            #f'/year/firstpublished?startDate={}&endDate={}'
        if 'latest' in input.keys()
            #latest X advisories

            
        elif input.keys()[0] in 'latest':
    
    def by_id(self):
        print('by id')
        
    def by_product(self):
        print('by product')
        
    def by_software(self):
        print('by software')
    
    def make_filter(input):
        #All advisories
            #by first_published
            #by last_published
            #by year
            #by severity rating
            #by impact score and date range
            #last x advisories
        #By Identifiers
            #by advisory id
            #by CVE id
            #by bug id
        #By Product
            #by product name combined with security advisory publication
            #by product
        #By Software
            #All available version of software
            #All available platform names
            #All advisories affecting a version of IOS
            #All advisories affecting a version of asa
            #Targeting a specific platform
            #Specific platform and advisory ID
        #Upon error generating filter, prompt user
        return