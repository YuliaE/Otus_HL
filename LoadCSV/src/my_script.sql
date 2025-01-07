\copy public.users from '/src/data.csv' (format csv, header false, delimiter ',', encoding 'UTF8');
\copy public.posts(post) from '/src/posts.txt' (format text, header false, encoding 'UTF8');



