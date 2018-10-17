###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_aff51f5e62_python-paramiko_fc27.nasl 11927 2018-10-16 12:17:30Z santu $
#
# Fedora Update for python-paramiko FEDORA-2018-aff51f5e62
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.875192");
  script_version("$Revision: 11927 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 14:17:30 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-15 07:14:27 +0200 (Mon, 15 Oct 2018)");
  script_cve_id("CVE-2018-1000805", "CVE-2018-7750");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for python-paramiko FEDORA-2018-aff51f5e62");
  script_tag(name:"summary", value:"Check the version of python-paramiko");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"Paramiko (a combination of the Esperanto
  words for 'paranoid' and 'friend') is a module for python 2.3 or greater that
  implements the SSH2 protocol for secure (encrypted and authenticated) connections
  to remote machines. Unlike SSL (aka TLS), the SSH2 protocol does not require
  hierarchical certificates signed by a powerful central authority. You may know
  SSH2 as the protocol that replaced telnet and rsh for secure access to remote
  shells, but the protocol also includes the ability to open arbitrary channels
  to remote services across an encrypted tunnel (this is how sftp works, for example).
");
  script_tag(name:"affected", value:"python-paramiko on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-aff51f5e62");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZBWZFBHEZWFCY6NL54XA46IXCXU2TESU");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"python-paramiko", rpm:"python-paramiko~2.3.3~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
