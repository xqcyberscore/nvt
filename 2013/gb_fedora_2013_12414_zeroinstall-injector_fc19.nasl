###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for zeroinstall-injector FEDORA-2013-12414
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.866654");
  script_version("$Revision: 9372 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:56:37 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-08-20 15:20:48 +0530 (Tue, 20 Aug 2013)");
  script_cve_id("CVE-2013-2099", "CVE-2013-2098");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Update for zeroinstall-injector FEDORA-2013-12414");

  tag_insight = "The Zero Install Injector makes it easy for users to install software
without needing root privileges. It takes the URL of a program and
runs it (downloading it first if necessary). Any dependencies of the
program are fetched in the same way. The user controls which version
of the program and its dependencies to use.

Zero Install is a decentralized installation system (there is no
central repository  all packages are identified by URLs),
loosely-coupled (if different programs require different versions of a
library then both versions are installed in parallel, without
conflicts), and has an emphasis on security (all package descriptions
are GPG-signed, and contain cryptographic hashes of the contents of
each version). Each version of each program is stored in its own
sub-directory within the Zero Install cache (nothing is installed to
directories outside of the cache, such as /usr/bin) and no code from
the package is run during install or uninstall. The system can
automatically check for updates when software is run.
";

  tag_affected = "zeroinstall-injector on Fedora 19";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "FEDORA", value: "2013-12414");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-July/111607.html");
  script_tag(name:"summary", value:"Check for the Version of zeroinstall-injector");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC19")
{

  if ((res = isrpmvuln(pkg:"zeroinstall-injector", rpm:"zeroinstall-injector~2.3~1.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
