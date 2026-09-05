# Provenance: erev0s/VAmPI get_by_title (fixed).
# repo: erev0s/VAmPI
# commit: 1713b54b601ad29582581eeda4b31fceb1319874
# parent: 1713b54b601ad29582581eeda4b31fceb1319874
# commit_url: https://github.com/erev0s/VAmPI/blob/1713b54b601ad29582581eeda4b31fceb1319874/api_views/books.py#L51
# cve: 
# license: MIT
# function: get_by_title
# relpath: api_views/books.py
# provenance: human
# mechanism: missing_auth_guard

def get_by_title(book_title):
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        if vuln:  # Broken Object Level Authorization
            book = Book.query.filter_by(book_title=str(book_title)).first()
            if book:
                responseObject = {
                    'book_title': book.book_title,
                    'secret': book.secret_content,
                    'owner': book.user.username
                }
                return Response(json.dumps(responseObject), 200, mimetype="application/json")
            else:
                return Response(error_message_helper("Book not found!"), 404, mimetype="application/json")
        else:
            user = User.query.filter_by(username=resp['sub']).first()
            book = Book.query.filter_by(user=user, book_title=str(book_title)).first()
            if book:
                responseObject = {
                    'book_title': book.book_title,
                    'secret': book.secret_content,
                    'owner': book.user.username
                }
                return Response(json.dumps(responseObject), 200, mimetype="application/json")
            else:
                return Response(error_message_helper("Book not found!"), 404, mimetype="application/json")
