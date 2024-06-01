from flask import Flask, request, render_template_string
import pickle
import numpy as np
import re

# Load the trained model (replace with your model loading logic)
model = pickle.load(open("models/phishing_model.pkl", "rb"))  # Assuming model saved as phishing_model.pkl

# Define blacklist (replace with your list of known phishing URLs)
BLACKLIST_URLS = [
    "https://telrgrame.xyz/",
    "http://instagramfx.vercel.app/",
    "https://customer-sp-jeanabarranger.pages.dev/help/contact/295376827684651",
    "https://security-ads-team-6dfd2.web.app/form-2122.html",
    "https://plum-efficient-peridot.glitch.me/public/n0h0t5.htm",
    "http://pub-699e84f217f5423c837b00ebdb05ca69.r2.dev/oiuytrt.html",
    "https://jp1.fjnpzh.top/",
    "https://wt20mh3sx.hier-im-netz.de/dh.html",
    "http://buildnfts-box.web.app/",
    "https://telegramsex-dft.pages.dev/",
    "https://act-aletaharrop6298.pages.dev/",
    "http://t.service.isuzucoco.com/t.aspx/subid/175246806/camid/1665956/linkid/323519/Default.aspx",
    "http://cumbersome-nice-othnielia.glitch.me/lamp.html",
    "http://pub-c821754538ab422a8c1368c76ce0b940.r2.dev/index.html",
    "http://corteza-boleyit-gramant.pages.dev/help/contact/716381447400133",
    "https://confirmed-graceful-hospital.glitch.me/public/n0h0t5.htm",
    "https://gaming-mantagalaxies.net/",
    "http://join-mantagalaxies.app/",
    "https://dgfesrter22.pages.dev/",
    "https://hazel-cerulean-sleep.glitch.me/jeep.html",
    "http://factual-cerulean-rutabaga.glitch.me/f6t7wegu.html",
    "https://elenmistoprak.com/835181182/Instagram.com.html",
    "http://gbwhats.in/",
    "https://nftsmintz.firebaseapp.com/",
    "https://eloquent34-gelato-de99d5-vd666.netlify.app/dev.html/",
    "https://courageous-numerous-galley.glitch.me/rain.html",
    "https://dulcet21-stroopwafel-0d9dca-vd686.netlify.app/dev.html/",
    "http://www.trustwallet.org.cn/download/",
    "https://rad-raindrop-c99tr74g.netlify.app/dev.html/",
    "https://help-for-business-cases-appeal-id-501.vercel.app/appeal_case_id",
    "https://www.pure-2.com/",
    "https://swissuporti3.site/ch/id-74634/index.html?logln-s-Wiss-com-conn",
    "https://mpgrup.ro/HT/WeTransfer.php/",
    "http://mpgrup.ro/HT/WeTransfer.php",
    "https://contact-center-31txgt6.netlify.app/id.html/",
    "http://pub-6a9768e0fffb4500b7328515b4979ae4.r2.dev/link1.html",
    "http://mmeneriimaa-peemmesaana-taabuungggassar.wixzey.com/",
    "https://customer-sp-logandaviau1.pages.dev/help/contact/18111546417294",
    "https://customer-sp-logandaviau1.pages.dev/help/contact/181115464172941",
    "http://yg-103.fjnpzh.top/",
    "https://web00-po.pages.dev/robots.txt",
    "http://w4p8m4rs5.hier-im-netz.de/de.html",
    "https://rocky-midi-tarn.glitch.me/public/n0h0t5.htm",
    "https://elenmistoprak.com/940293450/Instagram.com.html",
    "https://ipfs.io/ipfs/bafybeigvhe4mkl2k5o3zpkqomu2s5zk76ht44z5wz567p572zitwi7jzdq/index%20(2).html",
    "https://cloudflare-ipfs.com/ipfs/bafybeigvhe4mkl2k5o3zpkqomu2s5zk76ht44z5wz567p572zitwi7jzdq/index%20(2).html",
    "https://secure760-darkizitri809234.codeanyapp.com/Add/so/netfixx",
    "https://sugared-confirmed-dove.glitch.me/public/n0h0t5.htm",
    "http://2565select-fthcapital-plans6898.pages.dev/help/contact/713224475902463",
    "https://cloudflare-ipfs.com/ipfs/QmQEUpWpQ9uL9awStD1WdAm22EutAhWDHVYKUuZapV2fTB",
    "https://ipfs.io/ipfs/bafybeihsug4qpvruhzx2sr3q6aglivzltym6fbed446uvclkci6psuiqpe/2.html",
    "https://cloudflare-ipfs.com/ipfs/bafybeihsug4qpvruhzx2sr3q6aglivzltym6fbed446uvclkci6psuiqpe/2.html",
    "http://cmmurphy1277.mozellosite.com/",
    "https://shashwatvegeta.github.io/netflix-clone-",
    "https://assistance-with-verification-meta-30051414.pages.dev/",
    "http://micro-office.zapier.app/",
    "https://hkfirstloginfacebook.blogspot.com/?q=aWQ9c3AwbWVycy10ZWFtX2xhbmc9YXJfc2M9NDgzMF91c2VyPTEwMDc2https://hkfirstloginfacebook.blogspot.com/?q=aWQ9c3AwbWVycy10ZWFtX2xhbmc9YXJfc2M9NDgzMF91c2VyPTEwMDc2",
    "https://cerulean-lebkuchen-0699btrg.netlify.app/dev.html/",
    "http://www.uob.applerewardsstore.com/",
    "http://bafybeibvn2i2ux7r5csah6lpfp3qcfxqzqqqtlblnvp6hzuq2v4zl72bkm.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "https://elenmistoprak.com/5383793419/Instagram.com.html",
    "https://www.wewe.com.bd/portal/discovery/auth.html",
    "https://bt-106300.weeblysite.com/",
    "https://blue-resonance-2027.mmiloud.workers.dev/",
    "http://bafybeiarklkxs66sro7tkqars3b4xhyju6glyjpcwxcxz4g66wwfphkoby.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeic66v6a4sqeen5xn3us2b5ppcj2mkdtvxcormeta5ermqjle3fgri.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeidcsod7cswatbjfq5tcjr23p6edtqinj4jpvqupnwyljjgjqiluuy.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafkreifohjvzqw5hoeshawopuyabhhesney7aiwfyzuxuppvpjz5gugy6y.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeid65r2l3od2frvqpvffeo5sq3iju3bkri265zp75p5y33mdv2clny.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://qmpbsusuapzk2pknnwcgw5jdzk6sqmkdp7ventznqsvjgm.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeigtqpci7nbpjuduy7cwcndf64p5iwjl3xio5gu3l64bwrrcv5npwm.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeidwr3tj3efhf25yrzwrehhmfmndk5froed4oppllakipx7akg3foi.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeiarshkw3akbaqjrozky3jisecs6yauvsicafcsww2swfhs4uxcqbq.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeidewojdbhe4gi7rbtt7k4r2ncuroujdp6qo3meke46aistuwaq2o4.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeibzvd5jdlepz3kesmzuhyqpn7soieuqnnmzrwh63g2r4gx5563yuy.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://api.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeibk34jvz4nc6iofj4wkaeeo5vzhcksr5z2jay6n44asuvdh6hnv24.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeib5q34vp4flb6bjr3fmeia7yp5kksnakmshimak5c6x7zrddzdiu4.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeicxwdx4fmvfswqphwpn3j2entr3b5paalzo43o3kushh6iw7mxm3a.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeiaro52pza7whzov5mbjfclnailw4nharcamqpsxmbqshxbfjiuy3y.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeidkv4bv22p4vs76ogiar4v5zksgf447zcziyqzk4vwmpkymcx4hze.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeic4mp2ncfn5rfg225otgput46ta6kd2ff6ijh72guig4f5zkjlibq.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeigqqltjulznrxn2qpr43f5jpcyclv7fwxxm4ydap7rsde3666ewn4.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeielm5xfu53y5egg5azlz2tli5hsrwmb4huw2zrdlw2m6dtohonbem.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeiatosytzlbssddhyygynlvkxxcvnbelun3yunykjilzmf6zpnev4q.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeibagpmoi6d32hw4ulowu7fuwoosrnn7ystkzvptpnr26lrfpjuvvm.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeiaddyrhxtk7e3mwnihw6hm6ehkywcl4yt5azcjnzjvzrgqhty7rny.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://omniequivalence-com.ipns.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafkreih37evu7hmyrx3vswmtpi2tqf5kr6qnvddjieaba7y4cum6bpyn4y.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeidpeezpjbxfkj6q4xgurflhssehizqxyp2xm4ybgjuhmjhnbt244u.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeidvibzte5annlbgenua53a6x2qln636jbm6txwizvs5kvzzpahlty.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeigyuyrplqs6mbamuh7tietlxqdjxuxrltphi3jnow3qg4gzdpiidi.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeibkq2c2jzkmrwbx2ovoaw662cbhnrss4gfm55vgkl4jo4nmfwyzay.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "https://cf-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeibzmoj6kl2n5sxkigl6sn6nfkg2nb4kdfeyfjqqreslpts3cwrzqa.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeieswamx6bj67sx332d3ssf2jawin64jlfr66wzgqiijaqusktvmsu.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeihjrofh4ieyo5l2c4lsktdjnrye2nc7by4c2yhq2rf5pwi3yxq3fy.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeiapdjd6fxbbbv5h5dsmc7dtfjxahqltarc3vf6n2m7axddpatfph4.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeicmwlmwfwuuttg7uf6i2or5kmz3pqni5ucuapyo6yi2ixpi75wkii.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeie26zjmiy5c5dgjaiioz3fwr7qhf3r2rf4llk4vfeis5daeljhx5m.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeienqqzkpksljw6idsr4sjnbt2jwdv5umnb5ufl26my7z7ahssfvcm.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeihqwxoqu6ebfnvmrhva5ihsgxxj5bncj7pkkwsdp3bki5d4ujxrbe.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeidjxw4moiz5he4o6sq5x6zhe3yghjbldx7qetslk3wikwv7qwb7eu.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeigzyff7twovagb55axdwgrmh3ypiajgq2vet5jnrb733sqa4g6rpa.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeidhvndkzeqxfzjqfsjd6ke6z5qubpt4hhcddlobjdvyusjpxrrpta.ipfs.cloudflare-ipfs.com/ipfs/afybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeicpfmiezj3tuxbfxbq37fnjakcklu3hsg3uqanuzbtd6s2cjliuka.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeigu2nkurxmoovrhwwul6i7k3gni63k57ekqxbv4alkwiomb25hawy.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeihmkbksrorcurmjuhbvoaexpbd6p4inopxg5dll2w7dlmm6mpdc4y.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafyreihfqgkynasnoczluh5qpf34wus5lz3i2a6f3cbqmgpybqcxwazrim.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "https://luxury33-longma-739a27-vd213.netlify.app/dev.html/",
    "http://bafybeiaysi4s6lnjev27ln5icwm6tueaw2vdykrtjkwiphwekaywqhcjze.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeie7oqsnasrawlhp5zioh2kx3aecwvlzr736wqyo6qikxbwlzrzs3m.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeibc24stjihm6tsemfedx6l5zm44ksygtppf7girbb2f4siotlhgyu.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeibzdtkxjtcvli66qngqs5yxs2hkwl6mgsa4m6ncxi6zlewbceg46a.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeigjuwcq3rxm6mj73xy62ih6ppaxoovg4hn647ys4ypdbcf2rqq25q.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafkreiaeemvrjunhcs6v4h2b67jgpkbnjw2rgfpt7zfa2stizhxhjfr2ly.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeie4pgkswo6fd4gmnk4dbwme5vxc4cud5mzfmfg3lrb3v4yal53f64.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeigzpfn26zvqg7u7rurxqtvj2x6g7qtzg2squkh6y34p4vj6kqdtpq.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeigeqcjozpc56pfjpospn2niug5pcoe4xhhubhxuslfa37mulzxduy.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafyreieobzh55clbrfphdhhauqlropevyzzm2s7mvwynh7smduie4m6haq.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeiac7tdkx4wpvfdir5tcrvugide52ikm5idzhpnzcuq5rfyexp6vsy.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeid3uw2uedksrvivjieb373622m3nahufpqtzkbnsyt6sopgfkgb6i.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeibugvpz5kvzrbo5fneqa622pmykpzyknxxphukbpjtziqzjycyusu.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafybeibwzifw52ttrkqlikfzext5akxu7lz4xiwjgwzmqcpdzmp3n5vnbe.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "http://bafkreifdq4djzbmzjxooett2otjnwdkafjdvjgomr6tezrxt66eojzgi7m.ipfs.cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "https://jaikumar00.github.io/Netflix-Clone/",
    "http://pub-db48581206534286978d377a1accd9ee.r2.dev/blobgbexp.html",
    "http://bafybeigcouhnbnqy6w7pjkne3ncencdgyo4gdhkki3l2sywwjyzheqhto4.ipfs.dweb.link/",
    "http://pblishedaccs1st.ftp.sh/",
    "http://infofacturation503.wixsite.com/my-site-1",
    "https://freefireauxr9px.click-xx.my.id/",
    "http://dino-merah.tme-viral.com/",
    "https://162.241.159.36/admin/O365auth%20reviewdata%20memorystick/",
    "http://aviorinternational.com/.well-known/acme-challenge/XD/madeinchina/madeinchina/",
    "http://juem.pages.dev/",
    "https://ipfs.io/ipfs/bafybeie3yfvfyo7s5ik4v3clnzgcr42oxkp26i7lclf62dexxrj62ebzii/MS.html",
    "https://david-active5860.pages.dev/robots.txt",
    "http://pancakeswap.games/",
    "https://secure350.servconfig.com/~a373525/asp/",
    "https://secure350.servconfig.com/~a373525/asp/passid.html",
    "https://apply-remove.github.io/review_restriction_fb/second.html",
    "https://shorten.tv/MetaBusinessGuidance",
    "https://festadapitanga.com.br/image/g63xx/xM5ZunYgqst895443728403/3mail@b.c",
    "https://corteza-gramant-74335cn.pages.dev/help/contact/632740076502071",
    "http://aktiflkan.danaspaylater.my.id/",
    "https://47.76.175.241/",
    "https://telegrambots-rectify.pages.dev/",
    "https://telegrammivan1.pages.dev/",
    "https://bt-102958.square.site/",
    "https://att-106384-100733.weeblysite.com/",
    "https://kassynaver.pages.dev/",
    "http://item.savinganimals.shop/",
    "https://act-spaletaharrop629.pages.dev/",
    "http://rtm-att.directly.com/",
    "http://ewual7pkgjtkd.pages.dev/",
    "http://geminii-login.godaddysites.com/",
    "http://supportbusinverify.pages.dev/business",
    "https://elenmistoprak.com/832201646/Instagram.com.html",
    "https://cap.ths.mybluehost.me/vA/Pakkets/Checkout%20-%20APILayer_files/saved_resource(1).php",
    "https://cap.ths.mybluehost.me/vA/Pakkets/load.html",
    "https://red-ducks.static.domains/",
    "https://pollpursuit-vote-pro.pages.dev/connecting.html",
    "https://www.wewe.com.bd/portal/discovery/email.html",
    "http://www.sagligimsigortasi.com/portal/discrhytuyttydhdgfdhgjfcgsfqfgtfddgdgshsjajsjdjbtydhdgshsjajsjdj/",
    "http://shimmering-gnome-474btr.netlify.app/dev.html/",
    "http://pub-d90b4e6b37254e1687ebe94c4d177a68.r2.dev/payments0.html",
    "http://aletaharrop629-sp.pages.dev/",
    "http://radiosatelit.ro/impots.gouv/new/app/",
    "http://pub-fdc1193e0e5c4a4c83dbc78d6d8fb286.r2.dev/index.html",
    "http://pub-f8eed36d4f9147d4854ea40b3327a20d.r2.dev/Docusign-Index.html",
    "http://ipfs.io/ipfs/bafybeidgkzr2gy7npe4yonk6p7s4chmwvgd2cp7bk7u6llfwiutgvt77tq",
    "http://pub-3e37d43ee95941968ad3f6a346271f7e.r2.dev/index.html",
    "https://worker-purple-fb.cloudflare-da7.workers.dev/",
    "http://ipfs.io/ipfs/QmbzDnBvcCgnQuZS8zem3SwLuURyppNP6yX9wuvRdbteU6",
    "http://pub-91f18d0dbf4748fe892cde71a124c656.r2.dev/mabble.html",
    "http://pub-1735e6cb161e49a7925d5e84c1a4f75e.r2.dev/indexjs.html",
    "http://pub-8102e0f5b915499d81d19dd7d64fbcaf.r2.dev/indexjs%20(2).html",
    "http://pub-e081b364f16342a1bf2e1d37ebbb279e.r2.dev/index.html",
    "http://pub-151b42f43d0c49ffa6a5525cf23f3a67.r2.dev/zombie0J01.html",
    "http://david-active5860.pages.dev/",
    "https://thunderous-donut-401d73loi.netlify.app/dev.html/",
    "https://3707comprehensive-fthcapital2.pages.dev/robots.txt",
    "https://david-active5397.pages.dev/",
    "http://custom-sp-homkeiurow21.pages.dev/",
    "http://pub-78da3e699efa42a59b33c64ac8d6f7ba.r2.dev/index.html",
    "http://pub-076d2c6317804f5ab969093911feb686.r2.dev/most.html",
    "http://pub-66c7d34b92f6411f9df59e134d7de913.r2.dev/dse_sign.html",
    "https://atttt-103153.weeblysite.com/",
    "https://att-sign-in-100074.weeblysite.com/",
    "http://pub-682ad3b65d944376b919745aae3c56d4.r2.dev/document16.html",
    "http://pub-29a74f49f4734786b372ca257eb7eccb.r2.dev/EM.html",
    "https://nazymtabys.kz/",
    "http://ipfs.io/ipfs/QmXhWvW5tUVbb6Z5QbeNSTjP8L5FXyazGKKttxshtg3dbV",
    "http://ipfs.io/ipfs/QmZbQfzYvREUawUd7KrA3X9MK2ndVnUtQA7WQ8S6kTB2YX",
    "http://ireneimoo.wixstudio.io/mysite",
    "http://metiamasklogen.gitbook.io/us/",
    "https://notification-alert.pages.dev/",
    "http://dgftsjhfgfg.blogspot.com/?m=1",
    "http://sfsadffsdeeqw.blogspot.com/?m=1",
    "https://discoveronline.discoverloginacces.workers.dev/",
    "http://pub-b4c2008e832a425fb1d4769acece9da2.r2.dev/index.html",
    "http://gwynnegriffiths1.wixsite.com/my-site",
    "http://pub-9971dc08f52d40de9865350c6bfcf7a4.r2.dev/index.html",
    "https://rogers-107955.weeblysite.com/",
    "http://pub-fbd1129c0d8343e4ace9b67701571b50.r2.dev/index.htm",
    "http://mailupdate43.wixsite.com/t-mail",
    "https://pianetanegozi.com/",
    "https://biblioteca.sicrediprogresso.com.br/",
    "http://informasi-terupdate.my.id/my.php",
    "https://wtspp.open-sooursee.live/",
    "http://pub-789bcf87a76741cca66053b3d8031ed9.r2.dev/ll/index.html",
    "http://pub-cd18447ae7fc44a283955e5c78d52c85.r2.dev/index.html",
    "http://pub-59f3815d88f14724908fcf9460c3d579.r2.dev/dse_sign.html",
    "https://dhlvodafone.increso.it/pWBAkidk",
    "http://pub-9f9f409dc5b24db59c601399ae066056.r2.dev/Alldomain-indexfile.html",
    "http://pub-32ede30a004541d89f058a9827a0d63e.r2.dev/index.htm",
    "http://pub-7d190ee5edc94bd2be3fc3f9aae59e05.r2.dev/index.html",
    "https://fawgfwagaw45654.web.app/",
    "https://ipfs.io/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "https://cloudflare-ipfs.com/ipfs/bafybeidnmn5l6yu6dthtjyo56jd6tbu3c7xk2eira7u32ynvpxixr2sdya/lifeee.html",
    "https://lcs-preventieteam.com/sqi.php",
    "https://bunqveriflcaties.com/rd.php",
    "http://pub-721ffb4a70764d3bbfd40249af7a81b9.r2.dev/index%20(6).html",
    "http://ipfs.io/ipfs/QmS5EKaE3A4WATbVN96jQWbuxNxeUkTC64qndfLGV5Tou5",
    "http://pub-cbd1099f86e04e9c8e66432d9bd38a42.r2.dev/index.html",
    "https://imtoken-ys.top/",
    "http://pub-7cdc7603ad49449094bb0225fda114bd.r2.dev/index.html",
    "https://imtoken-android.com/",
    "http://openseaprojt-claims14.vercel.app/",
    "https://dhl-express-group.blogspot.it/",
    "http://sol-pw.pages.dev/connect",
    "http://sol-pw.pages.dev/connect.html",
    "http://send-us-review-request.surge.sh/",
    "http://pub-a381ecfa57ba480eb3a3aa6631ef3f2c.r2.dev/index.html",
    "https://ipfs.io/ipfs/bafybeihzxuygqecz2426zcxyowybmhuw4cdcaeg4n4hv6uw3jpdqg2akau/quoquodree.html",
    "http://cloudflare-ipfs.com/ipfs/bafybeihzxuygqecz2426zcxyowybmhuw4cdcaeg4n4hv6uw3jpdqg2akau/quoquodree.html",
    "http://yairix.github.io/Login-Instagram/",
    "https://elite-wallet.com/",
    "https://cs--33129-view-mail-ups.web.app/",
    "https://allegroyuxuan.com/",
    "http://ipfs.io/ipfs/QmfS23qgphdm5UvT6T65PGugjcoXFZJaKYxrVnJJXS2qqa",
    "https://att-1servermail.weeblysite.com/",
    "https://review-violation-apply-support.replit.app/next.html",
    "http://ipfs.io/ipfs/QmYdbpVksUmugNdxETx6j9ftRAV5AN1Auv7S1SRkmbSmcY",
    "https://gateway.lighthouse.storage/ipfs/QmRnZRU3im5vUFJwHSQT38TqxG58BxfHigdFE9qQRhgUKr/",
    "https://bcqulrn.paddlefishthebook.com/",
    "https://att-108340-107930.weeblysite.com/",
    "https://clinquant-buttercream-d4fa95.netlify.app/",
    "http://acuratlydltedfileeror.github.io/conterestedhigflow/jozgandoz-menthol/",
    "https://remove-restriction-from-page.github.io/khaleel",
    "https://imtoken-rm.top/",
    "https://3707comprehensive-fthcapital2.pages.dev/",
    "https://bernardmarket.com/",
    "https://netflix-clone-qk0b7xk4o-anirudhsinghbhadauria.vercel.app/",
    "http://nabi5853.github.io/Assignment-1---Netflix-/",
    "http://sign-in-100775.weeblysite.com/",
    "http://telegrpn.club/",
    "https://tkq20pih.wickedfitboston.com/",
    "http://pub-6eb67d4de01947a68990bc27764e7322.r2.dev/320th.html",
    "https://netflix-clone-8tofe8hh5-jaker94.vercel.app/",
    "http://110.141.52.21/",
    "https://cavkwi.paddlefishthebook.com/",
    "http://mj-api.kun-ai.com/",
    "https://att-100338.weeblysite.com/",
    "https://dyi2jk.webwave.dev/",
    "https://e5p6qh.webwave.dev/",
    "https://elenmistoprak.com/1327601801/Instagram.com.html",
    "https://elenmistoprak.com/1085066042/Instagram.com.html",
    "https://dbs-pay.art/",
    "http://biglobe5243.weebly.com/",
    "https://neurohex.xyz/",
    "https://www.020jinhuo.com/",
    "https://attinc-101223.weeblysite.com/",
    "https://dhl-express-group.blogspot.co.id/",
    "https://b495088f53799df8e0a7994c2ba64.pages.dev/",
    "https://cobasaja8899.online.pulsamurah555.shop/",
    "http://www.poornamtech.com/ims.php",
    "http://www.opnform.com/forms/my-form-o1alaf/",
    "http://mysteryhint4.vercel.app/",
    "https://17-12-2023-port80-worker.sonteleh.workers.dev/",
    "http://www.magdalenariquelme.com/wp-content/goods/",
    "https://www.appie.inc.nxvas.cn/mim/469415xa56k6x8y333j03dl75246oai3r8e589p4799w67371q.html",
    "http://claimx-hadiah10jt.company.biz.id/",
    "http://claim-hadiah-dana6336.xcxcx.my.id/",
    "https://bafkreibdytnxndeifgkl3e6hgzh5g57qgsv3gribtxf3yb5uegsebf4fdm.ipfs.dweb.link/",
    "https://bafkreibdytnxndeifgkl3e6hgzh5g57qgsv3gribtxf3yb5uegsebf4fdm.ipfs.cf-ipfs.com/",
    "https://shreyamast.github.io/Netflix/",
    "https://priyanshughost.github.io/Netflix/",
    "http://david-active765.pages.dev/",
    "http://grup-whatsapp8761.resminih.my.id/",
    "https://tv-perfneweali-houston.pages.dev/",
    "https://vimal-mudalagi.github.io/Netflix/",
    "https://frefiremy.g-e-t.biz.id/",
    "http://www.vctrust.in/",
    "https://bafybeidmkjeaz5xs4zjf2r5ffbdpq44gloca46sfvqnj6ubvbca3zxeqvu.ipfs.dweb.link/",
    "https://ibvxf47vfa.onrocket.site/ch/",
    "https://ibvxf47vfa.onrocket.site/ch/sms.php",
    "https://ibvxf47vfa.onrocket.site/ch/smserror.php",
    "https://discord.yizhuangren.com/",
    "https://pdffilesinv.pages.dev/",
    "http://jbq5am7.imvolleyball.org/",
    "http://mgftpz.shop/",
    "http://qyt11t23wgj9c26azf8y9z1zc3e6ryyudz2km4kk-no-google-referer.pages.dev/",
    "https://webzlynan-dana-id.from34.biz.id/",
    "https://worker-mute-unit-5da5.438749168.workers.dev/",
    "https://bafybeie3c5fmnf3xkm65adghkvyxjb634xam5j4r7r3mymzzt7lsokobba.ipfs.cf-ipfs.com/",
    "http://6remx6f6ocfzhexvf6cxjje0ky5wzktzv1ot0t9c7gwr4mc3ji80phqiya.pages.dev/ads-business-pages qwh1xc45zgexrjofruflggpq5idnotdvupuehsinn6sxqb5vwbkuysmo2r4k7mzl2sjfpmohvi6kj0jgvsn5xo1jw9xhchroxsh0bhefolhvl0wfsuzmoujyxwxi5uvccgutrq4jhed8b7ligvk4dz2bagrnjddrqorapucovxrz1ruahts4iw8gi6wte3yev",
    "https://www.appie.inc.nxvas.cn/mim/7575ak3336co45zuu631108e59t118mdv2y0c80h397v186wk9.html",
    "http://act-spaletaharrop629.pages.dev/help/contact/745925060207325",
    "https://cn.mebtx29.com/",
    "http://skyfabrics.in/",
    "http://planbic.unitru.edu.pe/index.html",
    "https://khj.ac.id/.tmb/mawartoto/",
    "http://arjun0525.github.io/netflix/",
    "https://item.savinganimals.shop/id/9ZTdx0a8AcgQrMN",
    "https://ntyj2.pages.dev/",
    "https://pub-359838c8e3ae4346a2978592c2639c53.r2.dev/blob%20(1).html",
    "https://sign-in-att-103747.weeblysite.com/",
    "https://pro-helpcontact6892.pages.dev/help/contact/859380372631517",
    "https://bafybeie2l3pfjibz6646h54hfxc5z5oisilt46pzchdtedr46hdu6aauby.ipfs.dweb.link/",
    "http://www.baxitzhamal.kz/",
    "https://trutly.v6.army/",
    "https://bafybeibhmsdggu4473b4qp3dcftktisw3ocoea5jkvvgqjg5fm4uw5dt6q.ipfs.dweb.link/",
    "https://pk11345.github.io/Netflix",
    "https://spring-butterfly-cbb9.ziyihou0002.workers.dev/",
    "http://corteza-bollin-boleyit.pages.dev/",
    "https://quintessential591-network-capital9.pages.dev/help/contact/814860031467964",
    "https://adminuser.locogp.com/",
    "https://drop-office-logs-signup-ref-voe-dillore-mill7qi-sikrow-djchd-id.vercel.app/logisrfid74335&id74335contextidEE0F70F6F8A2D8D2&  opidDBDB6BC40EBC",
    "https://aiswaryahaishu.github.io/netflix-responsive-1",
    "https://corteza-gramant-74335cn.pages.dev/help/contact/328298734370856",
    "https://yahoo-106018.weeblysite.com/",
    "http://clientscommunicationsorgne.vercel.app/",
    "http://yimjtjmsis.duckdns.org/en/main",
    "http://token-pockot.net/",
    "https://ipfs.io/ipfs/bafybeihzxuygqecz2426zcxyowybmhuw4cdcaeg4n4hv6uw3jpdqg2akau/quoquodree.html/",
    "https://cloudflare-ipfs.com/ipfs/bafybeihzxuygqecz2426zcxyowybmhuw4cdcaeg4n4hv6uw3jpdqg2akau/quoquodree.html/",
    "https://office365-b8f.pages.dev/",
    "https://cmkls21yyhfpo.pages.dev/",
    "https://bafybeibiri6akaf2pabdtm6fnlk2jnkmay5v6a5kaukpfc6mttlflk6oyq.ipfs.dweb.link/",
    "https://enabler-rgw.pages.dev/",
    "https://www.appie.inc.nxvas.cn/mim/z6u3bt9829m104742z4554d470f98rbm94t023vyc3fq1t4e57.html",
    "https://telegram-grupo-sexo-102.pages.dev/",
    "http://kartike1103.github.io/Netflix/",
    "http://amazon-tw.netlify.app/",
    "http://joeuni-ex.github.io/Netflix/",
    "https://helpstrezorbridge.gitbook.io/",
    "https://frost-7862.kaila1097.workers.dev/",
    "https://www.uspssmartparcellockers.tech/",
    "https://telegram-web.pages.dev/",
    "https://manga-netflix10737.tinyblogging.com.xx3.kz/",
    "http://tracking-paket-dpd.qs0.de/openid-connect/update.php",
    "https://zinzus.pages.dev/",
    "https://worker-autumn-sun-b04b.cadno.workers.dev/",
    "https://worker-white-glade-0e4b.a887556413454640.workers.dev/",
    "https://confirm-messeges.saojoninue.workers.dev/",
    "https://hello-world-patient-scene-f24a.antonio-cabral.workers.dev/",
    "https://weathered-pond-21d2.alwdqh1p.workers.dev/",
    "https://worker-dark-resonance-47b6.mewacot599.workers.dev/",
    "https://worker-polished-union-d954.carloscanejoo.workers.dev/",
    "https://yemi1.pages.dev/",
    "http://news.midas-redeem.com/",
    "http://s2hk7.shop/",
    "https://2a5788b8.yemi1.pages.dev/",
    "http://netzero-103169.weeblysite.com/",
    "http://imtoken-aw.com/",
    "http://netzero-webmail-108238.weeblysite.com/",
    "http://bt-login-102393.weeblysite.com/",
    "http://bt-home-105105.weeblysite.com/",
    "http://gumunilogi.mystrikingly.com/",
    "http://praveen0525.github.io/netflix/",
    "http://attmailwiwiw.weebly.com/",
    "http://att-107844-107795.weeblysite.com/",
    "http://unimatriken.com/",
    "http://aolmaiillogin.blogspot.ie/",
    "https://optusnet-com.blogspot.in/",
    "http://metamasskluginn.blogspot.com.co/",
    "http://aolmaiillogin.blogspot.mk/",
    "http://generatorfreeaccounts.blogspot.qa/",
    "https://marquemediallc.com/wp-content/jp/Fixed/index.php/",
    "http://makemillions.pw.ytwwrntym.com/",
    "https://telstra-109250.weeblysite.com/",
    "http://att-100218.weeblysite.com/",
    "http://coimbasprulog.mystrikingly.com/",
    "https://entertainwap.mywibes.com/",
    "http://att-102380.weeblysite.com/",
    "https://fjt4d0.webwave.dev/",
    "http://btinternet-109323.weeblysite.com/",
    "http://cmoss.techvalleyabbottabad.pk/",
    "https://edikhtgsbdc.weebly.com/",
    "http://metamasskluginn.blogspot.lt/",
    "http://aolmaiillogin.blogspot.tw/",
    "https://try6trytrtre.blogspot.com/",
    "https://try6trytrtre.blogspot.co.za/",
    "https://cn.122manx.com/",
    "http://metamaskinc.blogspot.co.at/",
    "https://74979-3102ca-039c0fa-beec4c-93ccffae.pages.dev/",
    "https://mysteryc1aim1.vercel.app/",
    "http://shedevr.risunok-concurss.shop/",
    "https://homeatt-101296.weeblysite.com/",
    "https://confirmation.meet-people.workers.dev/",
    "https://login-microsoftonline.pages.dev/",
    "http://a4vby.shop/",
    "http://telstra-100337.weeblysite.com/",
    "https://succes.pages.dev/",
    "http://aeme-website-v2-nqlbydo1x-ahmed-hazeems-projects.vercel.app/",
    "http://bafybeihs36fbluauydrnkud564pe2tpwgr2ywdc3dpcsqckwnkkykol6ci.ipfs.infura-ipfs.io/",
    "http://metamask-wallett.blogspot.pe/",
    "https://conebaesignin.gitbook.io/",
    "http://facebooksecurity.blogspot.pt/",
    "http://verification-100764.weeblysite.com/",
    "http://dapi.190823.xyz/",
    "https://feceboolk.blogspot.in/",
    "http://instagramprofiileurl.blogspot.co.ke/",
    "https://app.moonweell.finance/234348948/Import.php",
    "https://635080.playcode.io/",
    "https://square-smoke-4c62.4tjwj7mx.workers.dev/",
    "https://billowing-tree-b282.dattings-our.workers.dev/",
    "http://182.16.22.83/",
    "https://billowing-unit-3e82.kem-datings.workers.dev/",
    "http://late-mode-d662.qxjqc91d.workers.dev/",
    "http://bafkreigddcffv64fnpyhjcyfrrvtsbazbsmpoihorfhbzslx5dwocnq4ti.ipfs.dweb.link/",
    "http://metamaskinc.blogspot.fi/",
    "https://tokenpbpket.com/",
    "http://instagramprofiileurl.blogspot.ae/",
    "http://metamaskinc.blogspot.com.ar/",
    "http://instagramprofiileurl.blogspot.pe/",
    "http://metamaskinc.blogspot.com.uy/",
    "http://instagramprofiileurl.blogspot.pt/",
    "http://instagramprofiileurl.blogspot.tw/",
    "http://metamaskinc.blogspot.pt/",
    "https://swisscome.blogspot.li/",
    "http://swisscome.blogspot.com.by/",
    "https://swisscome.blogspot.it/",
    "https://swisscome.blogspot.ch/",
    "https://swisscome.blogspot.co.nz/",
    "http://tokenp0ckot.shop/",
    "https://mail-109392.weeblysite.com/",
    "http://t0kelp0cket.top/",
    "https://netzero-webmail-108087.weeblysite.com/",
    "https://netzero-webmail-104238.weeblysite.com/",
    "https://telstra-101091.weeblysite.com/",
    "http://csg1ph2b6cf1iz.imtokend.top/",
    "https://telstra-104069.weeblysite.com/",
    "https://telstra-100578.weeblysite.com/",
    "https://telstra-104158.weeblysite.com/",
    "https://telstra-102841.weeblysite.com/",
    "https://telstra-106415.weeblysite.com/",
    "https://telstra-101474.weeblysite.com/",
    "https://telstra-108709.weeblysite.com/",
    "https://telstra-105138.weeblysite.com/",
    "https://telstra-101217.weeblysite.com/",
    "https://telstra-105309.weeblysite.com/",
    "https://smtp.romtelecom.net/",
    "https://telstra-105417.weeblysite.com/",
    "https://3656www.com:8989/",
    "https://telstra-102857.weeblysite.com/",
    "https://9878681.com:8989/",
    "http://bafybeihv3bs2qzncto4r37u35qybxb6fyaz45wk2srhdihi3iyo2r7boba.ipfs.dweb.link/",
    "http://l1mnke8rob4xy2.imtokend.top/",
    "http://maiiliaaattt.weebly.com/",
    "https://telstra-102068.weeblysite.com/",
    "https://telstra-109219.weeblysite.com/",
    "https://telstra-104300.weeblysite.com/",
    "https://dj6n4f.webwave.dev/",
    "https://telstra-108366.weeblysite.com/",
    "https://netzero-103832.weeblysite.com/",
    "https://telstra-108912.weeblysite.com/",
    "https://telstra-104407.weeblysite.com/",
    "https://telstra-107215.weeblysite.com/",
    "https://telstra-101819.weeblysite.com/",
    "https://att-100249.weeblysite.com/",
    "https://netzero-webmail-105105.weeblysite.com/",
    "https://telstra-104581.weeblysite.com/",
    "https://mail-106907.weeblysite.com/",
    "https://telstra-105423.weeblysite.com/",
    "https://telstra-104386.weeblysite.com/",
    "https://webmail-100660.weeblysite.com/",
    "https://telstra-108485.weeblysite.com/",
    "https://telstra-106561.weeblysite.com/",
    "https://telstra-102707.weeblysite.com/",
    "https://wis.ukrfem.in.ua/",
    "http://77.91.78.80/",
    "https://webmail-100500.weeblysite.com/",
    "https://telstra-105270.weeblysite.com/",
    "https://telstra-103248.weeblysite.com/",
    "https://telstra-109995.weeblysite.com/",
    "https://mail-100778.weeblysite.com/",
    "https://telstra-101688.weeblysite.com/",
    "https://bt-108441.weeblysite.com/",
    "https://mail-106567.square.site/",
    "https://mail-106567.weeblysite.com/",
    "https://iioawe.za.com/optusedit/optus/online.html",
    "https://telstra-109487.weeblysite.com/",
    "https://telstra-101318.weeblysite.com/",
    "https://shegeinao.sa.com/",
    "https://swisscome.blogspot.cl//",
    "https://swisscome.blogspot.com.cy/",
    "https://webmail-109919.weeblysite.com/",
    "https://telstra-102965.weeblysite.com/",
    # ... (add more URLs)
]

# Function to extract features from the URL
def extract_features(url):
    features = []

    # Feature 1: Length of the URL
    features.append(len(url))

    # Feature 2: Presence of HTTPS
    features.append(1 if url.startswith("https://") else 0)

    # Feature 3: Presence of redirects
    features.append(1 if "redirect" in url.lower() else 0)

    # Feature 4: Presence of suspicious keywords
    suspicious_keywords = [
        'nobell', 'it', 'ffb', 'd', 'dca', 'cce', 'f', 'login', 'SkyPe', 'com', 'en', 'cgi', 'bin', 'verification', 'login', 'ffb', 'd', 'dca', 'cce', 'f', 'index', 'php', 'cmd', 'profile', 'ach', 'outdated', 'page', 'tmpl', 'p', 'gen', 'failed', 'to', 'load', 'nav', 'login', 'access'
    ]
    features.append(sum(word in url.lower() for word in suspicious_keywords))

    # Feature 5: Subdomain length
    subdomains = url.split('.')[:-2]
    subdomain_length = sum(len(subdomain) for subdomain in subdomains)
    features.append(subdomain_length)

    # Feature 6: Presence of IP address in URL
    features.append(1 if re.findall(r"\d+\.\d+\.\d+\.\d+", url) else 0)

    # Feature 7: Presence of hyphen in domain name
    features.append(1 if '-' in url.split('://')[1].split('.')[0] else 0)

    # Feature 8: Presence of urgency words
    urgency_words = ["urgent", "immediate", "verify now", "important"]
    features.append(sum(word in url.lower() for word in urgency_words))

    # Feature 9: Presence of suspicious substrings (optional)
    suspicious_substrings = ["login", "account", "security", "update", "confirmation"]
    features.append(sum(substring in url.lower() for substring in suspicious_substrings))

    # Handle potential mismatch in feature count
    if len(features) > 31:
        features = features[:31]  # Truncate to expected number
    elif len(features) < 31:
        features.extend([0] * (31 - len(features)))  # Pad with zeros

    return np.array(features).reshape(1, -1)

# Function to check if URL is likely phishing
def check_phishing(url):
    # Check if URL is in blacklist
    if url in BLACKLIST_URLS:
        return "Phishing"  # URL found in blacklist
    
    # Extract features from URL
    features = extract_features(url)
    
    # Predict using trained model
    prediction = model.predict(features)[0]
    
    if prediction == 1:
        return "Phishing"  # Model predicts phishing
    else:
        return "Legitimate"  # Model predicts legitimate

# Flask app setup
app = Flask(__name__)

# Route for home page
@app.route('/')
def home():
    return render_template_string(open('template.html').read())

# Route for checking URL
@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.form.get('url')

    if not url:
        return render_template_string(open('template.html').read(), error="No URL provided.")

    result = check_phishing(url)
    
    return render_template_string(open('template.html').read(), result=result, url=url)

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
