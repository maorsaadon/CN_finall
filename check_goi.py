import cgi

# get the values of the hostName and fileName parameters sent from the HTML form
form = cgi.FieldStorage()
hostName = form.getvalue("hostName")
fileName = form.getvalue("fileName")

# print the values of the parameters
print("Host Name:", hostName)
print("File Name:", fileName)
