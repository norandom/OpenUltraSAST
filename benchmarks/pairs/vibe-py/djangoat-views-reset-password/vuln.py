# Provenance: Contrast-Security-OSS/DjanGoat reset_password (vuln).
# repo: Contrast-Security-OSS/DjanGoat
# commit: 082c88bfefced508ae083b92b459c808f95e905e
# parent: 082c88bfefced508ae083b92b459c808f95e905e
# commit_url: https://github.com/Contrast-Security-OSS/DjanGoat/blob/082c88bfefced508ae083b92b459c808f95e905e/app/views/password_resets/views.py#L84
# cve: 
# license: MIT
# function: reset_password
# relpath: app/views/password_resets/views.py
# provenance: human
# mechanism: source_reaches_sink

def reset_password(request):
    if request.POST.get('user', '') != '':
        encoded_user = request.POST['user']
        user = pickle.loads(base64.b64decode(encoded_user))
        user.password = request.POST['password']
        user.save()
        messages.success(request, 'Your password has been updated')
    else:
        try:
            messages.error(request, 'Password did not reset')
        except:
            pass

    return redirect('/login')
