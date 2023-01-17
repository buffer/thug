#!/bin/bash

rm -rf doc
mv html doc

for file in $(find doc -type f); do
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sed -i s/_static/static/g $file;
        sed -i s/_sources/sources/g $file;
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        LC_CTYPE=C && LANG=C && sed -i '' 's/_static/static/g' $file;
        LC_CTYPE=C && LANG=C && sed -i '' 's/_sources/sources/g' $file;
    fi
done

mv doc/_sources doc/sources
mv doc/_static doc/static
