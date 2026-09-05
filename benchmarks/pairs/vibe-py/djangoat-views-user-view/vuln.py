# Provenance: Contrast-Security-OSS/DjanGoat user_view (vuln).
# repo: Contrast-Security-OSS/DjanGoat
# commit: 082c88bfefced508ae083b92b459c808f95e905e
# parent: 082c88bfefced508ae083b92b459c808f95e905e
# commit_url: https://github.com/Contrast-Security-OSS/DjanGoat/blob/082c88bfefced508ae083b92b459c808f95e905e/app/views/users/views.py#L74
# cve: 
# license: MIT
# function: user_view
# relpath: app/views/users/views.py
# provenance: human
# mechanism: source_reaches_sink

def user_view(request, user_id):
    if request.method == "POST":
        form = request.POST
        if not form:
            return HttpResponse("User " + str(user_id) + "POST")
        user_id_form = form['user_id']
        table_name = User.objects.model._meta.db_table
        # The order by is_admin='0' moves admin to the first in list
        # which allows sql injection
        users = User.objects.raw(
            "SELECT * FROM %s WHERE user_id='%s' ORDER BY is_admin='0'"
            % (table_name, user_id_form))
        try:
            user = users[0]
        except:
            return HttpResponse("User " + str(user_id_form) + " NOT FOUND")
        update = dict()
        err_msg = User.validate_update_form(form, user, update)
        if len(err_msg) > 0:
            messages.add_message(request, messages.INFO, err_msg)
        else:
            try:
                # skip hash_password if password not updated
                if "password" not in update:
                    User.objects.filter(pk=user.pk).update(**update)
                else:
                    user.__dict__.update(update)
                    user.save()
                messages.add_message(request, messages.INFO,
                                     "Successfully Updated")
            except Exception as e:
                messages.add_message(request, messages.INFO, str(e))
        return redirect("/users/%s/account_settings" % user_id,
                        permanent=False)

    else:
        return HttpResponse("User " + str(user_id) + " " + str(request.method))
