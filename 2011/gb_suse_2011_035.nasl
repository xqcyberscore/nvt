###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for glibc,pam-modules,libxcrypt,pwdutils SUSE-SA:2011:035
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "The implementation of the blowfish based password hashing method had
  a bug affecting passwords that contain 8bit characters (e.g.
  umlauts).  Affected passwords are potentially faster to crack via
  brute force methods CVE-2011-2483.

  SUSE's crypt() implementation supports the blowfish password hashing
  function (id $2a) and system logins by default also use this method.
  This update eliminates the bug in the $2a implementation. After
  installing the update existing $2a hashes therefore no longer match
  hashes generated with the new, correct implementation if the
  password contains 8bit characters. For system logins via PAM the
  pam_unix2 module activates a compat mode and keeps processing
  existing $2a hashes with the old algorithm. This ensures no user
  gets locked out. New password hashes are created with the id  &qt $2y &qt 
  to unambiguously identify them as generated with the correct
  implementation.

  Services that do not use PAM but do use crypt() to store passwords
  using the blowfish hash do not have such a compat mode. That means
  users with 8bit passwords that use such services will not be able to
  log in anymore after the update. As workaround administrators may
  edit the service's password database and change stored hashes from
  $2a to $2x. This will result in crypt() using the old algorithm.
  Users should be required to change their passwords to make sure they
  are migrated to the correct algorithm.

  FAQ:

  Q: I only use ASCII characters in passwords, am I a affected in any
  way?
  A: No.

  Q: What's the meaning of the ids before and after the update?
  A: Before the update:
  $2a -&gt; buggy algorithm

  After the update:
  $2x -&gt; buggy algorithm
  $2a -&gt; correct algorithm
  $2y -&gt; correct algorithm

  System logins using PAM have a compat mode enabled by default:
  $2x -&gt; buggy algorithm
  $2a -&gt; buggy algorithm
  $2y -&gt; correct algorithm

  Q: How do I require users to change their password on next login?
  A: Run the following command as root for each user:
  chage -d 0 &lt;username&gt;

  Q: I run an application that has $2a hashes in it's password database. Some
  users complain that they can not log in anymore.
  A: Edit the password database and change the  &qt $2a &qt  prefix of the affected users'
  hashes to  &qt $2x &qt . They will be able to log in again but should change their
  password ASAP.

  Q: How do I turn off the compat mode for system logins?
  A: Set BLOWFISH_2a2x=no in /etc/default/passwd";
tag_solution = "Please Install the Updated Packages.";

tag_impact = "weak password hashing algorithm";
tag_affected = "glibc,pam-modules,libxcrypt,pwdutils on openSUSE 11.3, openSUSE 11.4, SUSE SLES 9";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.850170");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-27 16:37:49 +0200 (Sat, 27 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name: "SUSE-SA", value: "2011-035");
  script_cve_id("CVE-2011-2483");
  script_name("SuSE Update for glibc,pam-modules,libxcrypt,pwdutils SUSE-SA:2011:035");

  script_tag(name:"summary", value:"Check for the Version of glibc,pam-modules,libxcrypt,pwdutils");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.11.3~12.17.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.11.3~12.17.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-html", rpm:"glibc-html~2.11.3~12.17.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.11.3~12.17.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-info", rpm:"glibc-info~2.11.3~12.17.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-locale", rpm:"glibc-locale~2.11.3~12.17.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-obsolete", rpm:"glibc-obsolete~2.11.3~12.17.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.11.3~12.17.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxcrypt", rpm:"libxcrypt~3.0.3~9.10.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxcrypt-devel", rpm:"libxcrypt-devel~3.0.3~9.10.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.11.3~12.17.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam-modules", rpm:"pam-modules~11.4~3.4.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pwdutils", rpm:"pwdutils~3.2.14~4.5.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pwdutils-plugin-audit", rpm:"pwdutils-plugin-audit~3.2.14~4.5.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pwdutils-rpasswd", rpm:"pwdutils-rpasswd~3.2.14~4.5.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-32bit", rpm:"glibc-32bit~2.11.3~12.17.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel-32bit", rpm:"glibc-devel-32bit~2.11.3~12.17.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-locale-32bit", rpm:"glibc-locale-32bit~2.11.3~12.17.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-profile-32bit", rpm:"glibc-profile-32bit~2.11.3~12.17.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxcrypt-32bit", rpm:"libxcrypt-32bit~3.0.3~9.10.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam-modules-32bit", rpm:"pam-modules-32bit~11.4~3.4.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pwdutils-rpasswd-32bit", rpm:"pwdutils-rpasswd-32bit~3.2.14~4.5.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.3")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.11.2~3.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.11.2~3.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-html", rpm:"glibc-html~2.11.2~3.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.11.2~3.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-info", rpm:"glibc-info~2.11.2~3.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-locale", rpm:"glibc-locale~2.11.2~3.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-obsolete", rpm:"glibc-obsolete~2.11.2~3.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.11.2~3.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxcrypt", rpm:"libxcrypt~3.0.3~5.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxcrypt-devel", rpm:"libxcrypt-devel~3.0.3~5.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.11.2~3.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam-modules", rpm:"pam-modules~11.3~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pwdutils", rpm:"pwdutils~3.2.10~2.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pwdutils-plugin-audit", rpm:"pwdutils-plugin-audit~3.2.10~2.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pwdutils-rpasswd", rpm:"pwdutils-rpasswd~3.2.10~2.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-32bit", rpm:"glibc-32bit~2.11.2~3.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel-32bit", rpm:"glibc-devel-32bit~2.11.2~3.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-locale-32bit", rpm:"glibc-locale-32bit~2.11.2~3.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-profile-32bit", rpm:"glibc-profile-32bit~2.11.2~3.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxcrypt-32bit", rpm:"libxcrypt-32bit~3.0.3~5.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam-modules-32bit", rpm:"pam-modules-32bit~11.3~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pwdutils-rpasswd-32bit", rpm:"pwdutils-rpasswd-32bit~3.2.10~2.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
