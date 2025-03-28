import numpy as np
import pandas as pd
import pickle
from sklearn.metrics.pairwise import cosine_similarity

# Load datasets with explicit dtype handling to avoid warnings
books = pd.read_csv('Dataset/Books.csv', dtype={'Year-Of-Publication': str, 'ISBN': str})
users = pd.read_csv('Dataset/Users.csv')
ratings = pd.read_csv('Dataset/Ratings.csv')

# Display first few rows of each dataset
print(books.head())
print(users.head())
print(ratings.head())

# Display dataset shapes
print(books.shape)
print(ratings.shape)
print(users.shape)

# Check for missing values
print(books.isnull().sum())
print(users.isnull().sum())
print(ratings.isnull().sum())

# Check for duplicate values
print(books.duplicated().sum())
print(ratings.duplicated().sum())
print(users.duplicated().sum())

# Merging books and ratings dataset on ISBN
ratings_with_name = ratings.merge(books, on='ISBN')

# Creating a dataframe with book title and number of ratings
num_rating_df = ratings_with_name.groupby('Book-Title').count()['Book-Rating'].reset_index()
num_rating_df.rename(columns={'Book-Rating': 'num_ratings'}, inplace=True)
print(num_rating_df)

# Calculating the average rating (ensuring only numeric values are used)
avg_rating_df = ratings_with_name.groupby('Book-Title')['Book-Rating'].mean().reset_index()
avg_rating_df.rename(columns={'Book-Rating': 'avg_rating'}, inplace=True)
print(avg_rating_df)

# Merging num_rating_df and avg_rating_df
popular_df = num_rating_df.merge(avg_rating_df, on='Book-Title')
print(popular_df)

# Filtering books with num_ratings > 250 and displaying top 50 books
popular_df = popular_df[popular_df['num_ratings'] >= 250].sort_values('avg_rating', ascending=False).head(50)

# Removing duplicate book titles and selecting relevant columns
popular_df = popular_df.merge(books, on='Book-Title').drop_duplicates('Book-Title')[
    ['Book-Title', 'Book-Author', 'Image-URL-M', 'num_ratings', 'avg_rating']]
print(popular_df)

# Selecting users who have given ratings to more than 200 books
x = ratings_with_name.groupby('User-ID').count()['Book-Rating'] > 200
selected_users = x[x].index

# Filtering ratings for selected users
filtered_rating = ratings_with_name[ratings_with_name['User-ID'].isin(selected_users)]

# Selecting books that have more than 50 ratings
y = filtered_rating.groupby('Book-Title').count()['Book-Rating'] >= 50
famous_books = y[y].index

final_ratings = filtered_rating[filtered_rating['Book-Title'].isin(famous_books)]

# Creating a pivot table
pt = final_ratings.pivot_table(index='Book-Title', columns='User-ID', values='Book-Rating')
pt.fillna(0, inplace=True)
print(pt)

# Computing cosine similarity
similarity_scores = cosine_similarity(pt)
print(similarity_scores.shape)


# Recommendation function with error handling
def recommend(book_name):
    if book_name not in pt.index:
        return "Book not found in dataset."

    # Fetch index
    index = np.where(pt.index == book_name)[0][0]
    similar_items = sorted(list(enumerate(similarity_scores[index])), key=lambda x: x[1], reverse=True)[1:5]

    data = []
    for i in similar_items:
        item = []
        temp_df = books[books['Book-Title'] == pt.index[i[0]]]
        item.extend(list(temp_df.drop_duplicates('Book-Title')['Book-Title'].values))
        item.extend(list(temp_df.drop_duplicates('Book-Title')['Book-Author'].values))
        item.extend(list(temp_df.drop_duplicates('Book-Title')['Image-URL-M'].values))
        data.append(item)

    return data


print(recommend('1984'))

# Saving required files using pickle
pickle.dump(popular_df, open('popular.pkl', 'wb'))
books.drop_duplicates('Book-Title', inplace=True)
pickle.dump(pt, open('pt.pkl', 'wb'))
pickle.dump(books, open('books.pkl', 'wb'))
pickle.dump(similarity_scores, open('similarity_scores.pkl', 'wb'))
