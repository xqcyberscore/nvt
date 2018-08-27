###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_2818fc5308_rsyslog_fc27.nasl 11110 2018-08-25 05:03:07Z santu $
#
# Fedora Update for rsyslog FEDORA-2018-2818fc5308
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
  script_oid("1.3.6.1.4.1.25623.1.0.874967");
  script_version("$Revision: 11110 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-25 07:03:07 +0200 (Sat, 25 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-19 06:50:29 +0200 (Sun, 19 Aug 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for rsyslog FEDORA-2018-2818fc5308");
  script_tag(name:"summary", value:"Check the version of rsyslog");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"Rsyslog is an enhanced, multi-threaded
syslog daemon. It supports MySQL, syslog/TCP, RFC 3195, permitted sender lists,
filtering on any message part, and fine grain output format control. It is compatible
with stock sysklogd and can be used as a drop-in replacement. Rsyslog is simple
to set up, with advanced features suitable for enterprise-class, encryption-protected
syslog relay chains.
");
  script_tag(name:"affected", value:"rsyslog on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-2818fc5308");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PGNY5YIWUMNC5U2HCH7SVG5TXHDW7ODE");
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

  if ((res = isrpmvuln(pkg:"rsyslog", rpm:"rsyslog~8.37.0~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
