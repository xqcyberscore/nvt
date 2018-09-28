#
# This script was written by Thomas Reinke <reinke@securityspace.com>
#
# Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
# rpmcheck is intended to provide a quick way to verify that
# a given rpm, if it is installed, is up to date. The function
# isrpmvuln returns 0 if it is not installed or is installed
# but up to date, and returns 1 if it is installed and vulnerable

# This variable is defined at inclusion time. It's declared global and is set
# to True if isrpmvuln() is called for an OS version and a package name that
# match the target's configuration. It allows the callers to distinguish
# between non-installed packages and packages installed but not vulnerable.
__pkg_match = FALSE;

# Global keys to avoid that we're repeatedly asking redis for something we already know
global_var __rpm_ssh_release, __rpm_ssh_pkgs;

# @brief returns the current release string of the target saved within the KB (ssh/login/release).
#
# @return a string containing the current release of the target or an empty string if no release
#         string exists in the KB.
#
# @todo Maybe move into a spearate (new) include if other pkg-lib-*.inc includes needs this as well.
#
function rpm_get_ssh_release() {

  local_var rls;

  if( ! isnull( __rpm_ssh_release ) ) {
    rls = string( __rpm_ssh_release );
  } else {
    rls = string( get_kb_item( "ssh/login/release" ) );
    __rpm_ssh_release = rls;
  }
  return rls;
}

# Example call: isrpmvuln(pkg:"gnutls-utils", rpm:"gnutls-utils~1.4.1~3", rls:"FC6")
function isrpmvuln(pkg, rpm, rls) {
    local_var a, b, kbrls, pat, matches, checkshorta, checkshortb, rc, norm_pkg, report;
    # Check that we have the data for this release.
    kbrls = get_kb_item("ssh/login/release");
    if(kbrls!=rls) {
	return NULL;
    }
    rpms = get_kb_item("ssh/login/rpms");
    if(!rpms) return NULL;

    # Must include in the package search leading \n or ; to prevent
    # overly permissive search (e.g. search for 'ash' must not match 'bash')

    pat = string("[\n;](", pkg, "~[^;]+);");
    matches = eregmatch(pattern:pat, string:rpms);
    if(isnull(matches)) {
	return NULL;
    }
    
    ## If kernel package Found this loop will check for every installed versions of kernel package
    ## and reports as soon as it finds the first vulnerable Version.
    if(matches[1] =~ "^kernel~+")
    {
      pkg_name = split(rpms, sep:";");
      
      foreach pkgs (pkg_name)
      {
        if(eregmatch(pattern:"^kernel~+", string:pkgs))
        {
          a = eregmatch(pattern:"^kernel~[^;]+", string:pkgs);         
          report = kernel_packge_check(a:a[0], b:rpm, pkg:pkg);
          if(report){
            report1 += report + '\n' ;
          }
        }
      }
      return report1;
    }
    
    #security_message(0, data: "Comparing " + matches[1] + " against " + rpm);

    # Ok...revcomp handles almost all situations intellligently. But,
    # it can get caught on the following two string example:
    #    a:a="kernel~2.6.9~89.EL"; b="kernel~2.6.9~89.0.20.EL";
    # One would expect 'a' to be < (older than) 'b'.  However, in this
    # case revcomp differentiates the 'E' from the '0', and thinks that
    # that b is as a result older (lexicographically less than) a.
    # This is the only situation we've seen where this type of suffix
    # causes problems.  So, as a patch, we solve the problem locally 
    # BEFORE we call revcomp, by stripping from both strings the trailing
    # '.EL[0-9]*' suffix, but only if both strings have the identical suffix.
    # If we find other systems where this type of problem occurred, it may
    # make sense to consider if we should be stripping equal trailing strings
    # from the a/b parameters within revcomp. For now, though we'll do it here.

    a = matches[1];
    b = rpm;

    ## Splitting Package name and version
    ## Because the below replace _ with .(Dot) condition replaces
    ## _ in package name also
    asubstr = substr(a, strlen(pkg)+1, strlen(a));
    bsubstr = substr(b, strlen(pkg)+1, strlen(b));

    ## To replace _ with .(Dot)
    ## Because Version match fails in some case where version is having _(underscore)
    if(bsubstr =~ 'el[0-9]{1}_[0-9]{1}' && asubstr !~ 'el[0-9]{1}_[0-9]{1}')
      bsubstr = str_replace(string:bsubstr, find:'_', replace:'.');

    else if(asubstr =~ 'el[0-9]{1}_[0-9]{1}' && bsubstr !~ 'el[0-9]{1}_[0-9]{1}')
      asubstr = str_replace(string:asubstr, find:'_', replace:'.');

    ## Combining package name and version
    a = pkg + '~' + asubstr;
    b = pkg + '~' + bsubstr;

    checkshorta = eregmatch(pattern:"^(.*)[.]([Ee][Ll][0-9]*)$", string:a);
    checkshortb = eregmatch(pattern:"^(.*)[.]([Ee][Ll][0-9]*)$", string:b);
    if(!isnull(checkshorta) && !isnull(checkshortb)) {
	if(checkshorta[2]==checkshortb[2]) {
	    a = checkshorta[1];
	    b = checkshortb[1];
	}
    }

    if( eregmatch( pattern:"\.[0-9]{1}\.el[0-9]{1}", string:a ) && ! eregmatch( pattern:"\.[0-9]{1}\.el[0-9]{1}", string:b ) )
    {
      b = ereg_replace( pattern:"(\.el[0-9]{1})", replace:".0\1", string:b );
    }

    __pkg_match = TRUE;

    # Now proceed with the normal revision comparison
    rc = revcomp(a:a, b:b);
    if(rc<0) {
	norm_pkg = "";
	foreach comp (split(matches[1], sep: "~", keep:0)) {
	    norm_pkg = string(norm_pkg,"-",comp);
	}
	norm_pkg = substr(norm_pkg, 1);
	report = "Package " + pkg + " version " +
		 norm_pkg + ' is installed which is known to be vulnerable.\n';
	return report;
    }
    return NULL;
}

function kernel_packge_check(a, b, pkg)
{

    # TODO: Remove once openvas-nasl-lint can handle such a missing include
    # from within the same include.
    if(!defined_func("revcomp")) include("revisions-lib.inc");

    local_var a, b, pkg;

    vuln_pkg = a;

    asubstr = substr(a, strlen(pkg)+1, strlen(a));
    bsubstr = substr(b, strlen(pkg)+1, strlen(b));

    ## To replace _ with .(Dot)
    ## Because Version match fails in some case where version is having _(underscore)
    if(bsubstr =~ 'el[0-9]{1}_[0-9]{1}' && asubstr !~ 'el[0-9]{1}_[0-9]{1}')
      bsubstr = str_replace(string:bsubstr, find:'_', replace:'.');

    else if(asubstr =~ 'el[0-9]{1}_[0-9]{1}' && bsubstr !~ 'el[0-9]{1}_[0-9]{1}')
      asubstr = str_replace(string:asubstr, find:'_', replace:'.');

    ## Combining package name and version
    a = pkg + '~' + asubstr;
    b = pkg + '~' + bsubstr;

    checkshorta = eregmatch(pattern:"^(.*)[.]([Ee][Ll][0-9]*)$", string:a);
    checkshortb = eregmatch(pattern:"^(.*)[.]([Ee][Ll][0-9]*)$", string:b);
    if(!isnull(checkshorta) && !isnull(checkshortb)) {
        if(checkshorta[2]==checkshortb[2]) {
            a = checkshorta[1];
            b = checkshortb[1];
        }
    }
    
    __pkg_match = TRUE;


    # Now proceed with the normal revision comparison
    rc = revcomp(a:a, b:b);
    if(rc<0) {
        norm_pkg = "";
        foreach comp (split(vuln_pkg, sep: "~", keep:0)) {
            norm_pkg = string(norm_pkg,"-",comp);
        }
        norm_pkg = substr(norm_pkg, 1);
        report = "Package " + pkg + " version " +
                 norm_pkg + ' is installed which is known to be vulnerable.\n';
        return report;
    }
    return NULL;
}
