# Provenance: Contrast-Security-OSS/DjanGoat reset_password (fixed).
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

def forgot_password(request):
    qset = User.objects.filter(email=request.POST.get('email', ''))
    if len(qset) > 0:
        user = qset.first()
        messages.success(request, 'An email was sent to reset your password!')
        password_reset_mailer(request, user)
    else:
        try:
            messages.error(request, 'We do not have the email in our system')
        except:
            pass

    return redirect('/login')
