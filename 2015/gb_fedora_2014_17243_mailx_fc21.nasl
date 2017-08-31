###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mailx FEDORA-2014-17243
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.868698");
  script_version("$Revision: 6630 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:34:32 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-01-05 14:43:23 +0100 (Mon, 05 Jan 2015)");
  script_cve_id("CVE-2004-2771", "CVE-2014-7844");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Update for mailx FEDORA-2014-17243");
  script_tag(name: "summary", value: "Check the version of mailx");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Mailx is an enhanced mail command, which provides the functionality
of the POSIX mailx command, as well as SysV mail and Berkeley Mail
(from which it is derived).

Additionally to the POSIX features, mailx can work with Maildir/ e-mail
storage format (as well as mailboxes), supports IMAP, POP3 and SMTP
protocols (including over SSL) to operate with remote hosts, handles mime
types and different charsets. There are a lot of other useful features,
see mailx(1).

And as its ancient analogues, mailx can be used as a mail script language,
both for sending and receiving mail.

Besides the 'mailx' command, this package provides 'mail' and 'Mail'
(which should be compatible with its predecessors from the mailx-8.x source),
as well as 'nail' (the initial name of this project).
");
  script_tag(name: "affected", value: "mailx on Fedora 21");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "FEDORA", value: "2014-17243");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-January/147445.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC21")
{

  if ((res = isrpmvuln(pkg:"mailx", rpm:"mailx~12.5~14.fc21", rls:"FC21")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
