###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for w3m FEDORA-2017-2e6b693937
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
  script_oid("1.3.6.1.4.1.25623.1.0.872480");
  script_version("$Revision: 6634 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 09:32:24 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-03-14 05:52:35 +0100 (Tue, 14 Mar 2017)");
  script_cve_id("CVE-2016-9422", "CVE-2016-9423", "CVE-2016-9424", "CVE-2016-9425",
                "CVE-2016-9428", "CVE-2016-9426", "CVE-2016-9429", "CVE-2016-9430",
                "CVE-2016-9431", "CVE-2016-9432", "CVE-2016-9433", "CVE-2016-9434",
                "CVE-2016-9435", "CVE-2016-9436", "CVE-2016-9437", "CVE-2016-9438",
                "CVE-2016-9439", "CVE-2016-9440", "CVE-2016-9441", "CVE-2016-9442",
                "CVE-2016-9443", "CVE-2016-9622", "CVE-2016-9623", "CVE-2016-9624",
                "CVE-2016-9625", "CVE-2016-9626", "CVE-2016-9627", "CVE-2016-9628",
                "CVE-2016-9629", "CVE-2016-9631", "CVE-2016-9630", "CVE-2016-9632",
                "CVE-2016-9633");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for w3m FEDORA-2017-2e6b693937");
  script_tag(name: "summary", value: "Check the version of w3m");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value: "The w3m program is a pager (or text file 
  viewer) that can also be used as a text-mode Web browser. W3m features include 
  the following: when reading an HTML document, you can follow links and view 
  images using an external image viewer its internet message mode determines the 
  type of document from the header if the Content-Type field of the document is 
  text/html, the document is displayed as an HTML document you can change a URL 
  description like &#39 http://hogege.net&#39 in plain text into a link to that 
  URL. If you want to display the inline images on w3m, you need to install 
  w3m-img package as well. "); 
  script_tag(name: "affected", value: "w3m on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-2e6b693937");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YSOH6NVKCFJP4GSVXHBDWHLEJ24W6HWV");
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

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.3~30.git20170102.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}