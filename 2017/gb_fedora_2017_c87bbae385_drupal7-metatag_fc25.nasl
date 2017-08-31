###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for drupal7-metatag FEDORA-2017-c87bbae385
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
  script_oid("1.3.6.1.4.1.25623.1.0.872453");
  script_version("$Revision: 6634 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 09:32:24 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-03-09 05:06:56 +0100 (Thu, 09 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for drupal7-metatag FEDORA-2017-c87bbae385");
  script_tag(name: "summary", value: "Check the version of drupal7-metatag");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value: "The Metatag module allows you to 
  automatically provide structured metadata, aka 'meta tags', about your website. 
  In the context of search engine optimization, when people refer to meta tags 
  they are usually referring to the meta description tag and the meta keywords tag 
  that may help improve the rankings and display of your site in search engine 
  results. Meta tags have additional uses like the Open Graph Protocol used by 
  Facebook, specifying the canonical location of content across multiple URLs or 
  domains. This project is the designated Drupal 7 a from-the-ground-up rewrite 
  and successor of the Nodewords module. This package provides the following 
  Drupal modules: * metatag * metatag_context (requires drupal7-context) * 
  metatag_dc * metatag_devel * metatag_facebook * metatag_google_plus * 
  metatag_opengraph * metatag_panels (requires drupal7-ctools and drupal7-token, 
  as well as manual install of panels) * metatag_twitter_cards * metatag_views 
  (requires drupal7-views) "); 
  script_tag(name: "affected", value: "drupal7-metatag on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-c87bbae385");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/27LADRZVSHV4M4OGJ2UB6URW3ENE6IXK");
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

  if ((res = isrpmvuln(pkg:"drupal7-metatag", rpm:"drupal7-metatag~1.21~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}