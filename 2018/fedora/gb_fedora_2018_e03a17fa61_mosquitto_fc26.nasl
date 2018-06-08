###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_e03a17fa61_mosquitto_fc26.nasl 10145 2018-06-08 14:34:24Z asteins $
#
# Fedora Update for mosquitto FEDORA-2018-e03a17fa61
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
  script_oid("1.3.6.1.4.1.25623.1.0.874320");
  script_version("$Revision: 10145 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-08 16:34:24 +0200 (Fri, 08 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-04-03 09:01:13 +0200 (Tue, 03 Apr 2018)");
  script_cve_id("CVE-2017-7651", "CVE-2017-7652");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mosquitto FEDORA-2018-e03a17fa61");
  script_tag(name: "summary", value: "Check the version of mosquitto");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Mosquitto is an open source message broker 
that implements the MQ Telemetry Transport protocol version 3.1 and 3.1.1 MQTT 
provides a lightweight method of carrying out messaging using a publish/subscribe 
model. This makes it suitable for 'machine to machine' messaging such as with 
low power sensors or mobile devices such as phones, embedded computers or 
micro-controllers like the Arduino.
");
  script_tag(name: "affected", value: "mosquitto on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-e03a17fa61");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RYEDVPCR6ICVW23636D3QSTT3FLZNXYA");
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

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"mosquitto", rpm:"mosquitto~1.4.15~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
