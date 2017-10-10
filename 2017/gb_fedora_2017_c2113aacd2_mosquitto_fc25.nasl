###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mosquitto FEDORA-2017-c2113aacd2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.872760");
  script_version("$Revision: 7335 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-02 13:53:53 +0200 (Mon, 02 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-06-13 13:16:35 +0200 (Tue, 13 Jun 2017)");
  script_cve_id("CVE-2017-7650");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mosquitto FEDORA-2017-c2113aacd2");
  script_tag(name: "summary", value: "Check the version of mosquitto");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Mosquitto is an open source message broker 
that implements the MQ Telemetry Transport protocol version 3.1 and 3.1.1 MQTT 
provides a lightweight method of carrying out messaging using a publish/subscribe 
model. This makes it suitable for 'machine to machine' messaging such as with 
low power sensors or mobile devices such as phones, embedded computers or 
micro-controllers like the Arduino.");
  script_tag(name: "affected", value: "mosquitto on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-c2113aacd2");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LHTF67B7ITYSZJPGCR4ZS7IC6F6JTPFN");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"mosquitto", rpm:"mosquitto~1.4.12~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
