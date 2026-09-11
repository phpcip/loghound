# Third-party asset: the world outline

`world.json` is the basemap behind the country bubbles on the Networks view. It is the only
map data in Loghound and it is committed here on purpose: the panel must work air-gapped,
behind a Content-Security-Policy that allows no outside origin, so there is no tile server and
no CDN anywhere in this product.

## Provenance

* **Source:** Natural Earth, `ne_110m_admin_0_countries` (Admin 0 – Countries, 1:110m).
* **Upstream:** <https://www.naturalearthdata.com/> — vector releases are distributed at
  <https://github.com/nvkelso/natural-earth-vector>.
* **Licence:** public domain. Natural Earth states: "All versions of Natural Earth raster and
  vector map data found on this website are in the public domain. You may use the maps in any
  manner, including modifying the content and design, electronic dissemination, and offset
  printing. The primary authors, Tom Patterson and Nathaniel Vaughn Kelso, and all other
  contributors renounce all financial claim to the maps and invite you to use them for
  personal, educational, and commercial purposes. No permission is needed to use Natural
  Earth. Crediting the authors is unnecessary."

Public domain is why this source and not another: the repository is MIT and an attribution
requirement on a bundled asset would be inherited by everyone who forks it.

## What was changed

The upstream file is 838 KB. This copy is 155 KB, and the reduction is all structural rather
than a loss of outline detail that matters at the size this is drawn:

* **Every property removed but one.** Each feature keeps `properties.name`, set to the
  country's ISO 3166-1 alpha-2 code (`ISO_A2_EH`, falling back to `ISO_A2`). That is the key
  the panel already uses for a country everywhere else, and it is what `echarts.registerMap`
  matches a region by. The English name is not in here: it comes from `src/Geo/Countries.php`,
  which is the one table behind every country name in the product.
* **Coordinates rounded to two decimal places**, about a kilometre at the equator, which is
  well under a pixel on a world map of this size.
* **Repeated consecutive points dropped**, and any ring left with fewer than four points
  removed with it.
* **Antarctica dropped.** It is a large share of the file, it occupies the bottom of every
  frame, and no session has ever been geolocated to it.
* Two features carry no ISO code upstream (`N. Cyprus`, `Somaliland`) and are not included,
  because a region the panel cannot key by code cannot be matched to a count.

Regenerating it is a matter of taking the upstream GeoJSON and applying those five steps; the
result must stay under a couple of hundred kilobytes, and it must keep `properties.name` as the
alpha-2 code or the bubbles will not land on their countries.
