#!/bin/bash

rm -rf doc
mv html doc

for file in $(find doc -type f); do 
	sed -i s/_static/static/g $file; 
	sed -i s/_sources/sources/g $file;	
done

mv doc/_sources doc/sources
mv doc/_static doc/static
