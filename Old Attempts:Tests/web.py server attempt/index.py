#!/usr/bin/python
#
#  Copyright (c) 2014 Keely Hill. All rights reserved.

import web

import json

from web import form


import sys
sys.path.append("/Users/Keely/Developer/Auto Home/autohome")
import saver

sequences = saver.Sequences().savedSequencesList

render = web.template.render('templates/')

urls = (
		'/', 'Index'
)

app = web.application(urls, globals())


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False

class Index:
	
	def GET(self):
		head = render.head()
		return render.index(head, sequences)

	def POST(self):
		type = web.input().type
		data = web.input().data
		
		if type == "sequence.name": saver.Sequences().sequenceWithName(data).run()
		elif type == "sequence.edit":
			return render.sequence(render.head(), saver.Sequences().sequenceWithName(data))
		elif type == "sequence.save":
			rawData = json.loads(data)
	
			sequenceName = rawData.partition(':')[0]
			jsonActions = json.loads(rawData.partition(':')[2]) # an array
			
			saver.Sequences().setActionsDictForSequenceWithName(jsonActions, sequenceName)

			web.seeother('/')
		elif type == "sequence.newAction":
			pass




if __name__ == "__main__":
	app.run()










