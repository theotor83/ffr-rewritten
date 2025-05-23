# Generated by Django 5.1.6 on 2025-04-21 14:05

from django.db import migrations
from django.utils import timezone
from dotenv import load_dotenv
import os

load_dotenv()

def create_user_and_profile(apps, schema_editor):
    # Get historical models
    User = apps.get_model('auth', 'User')
    Profile = apps.get_model('forum', 'Profile')
    Forum = apps.get_model('forum', 'Forum')
    ForumGroup = apps.get_model('forum', 'ForumGroup')
    Topic = apps.get_model('forum', 'Topic')
    Category = apps.get_model('forum', 'Category')
    Post = apps.get_model('forum', 'Post')
    TopicReadStatus = apps.get_model('forum', 'TopicReadStatus')

    if ForumGroup.objects.filter(name="Springlock").exists():
        return  # If the group already exists, we don't need to run this migration again

    env_password = os.getenv('ADMIN_PASSWORD', 'password_not_found')  # Default password if not set in .env
    if env_password == 'password_not_found':
        raise ValueError("ADMIN_PASSWORD not found in .env file. Please set it.")
    
    admin_username = os.getenv('ADMIN_USERNAME', 'admin')  # Default username if not set in .env
    if admin_username == 'admin':
        print("Using default admin username 'admin'. If this is not intended, please set ADMIN_USERNAME in .env file.")

    # Create the Forum "UTF" (required by Profile's save() method)
    if Forum.objects.filter(name='UTF').exists():
        UTF = Forum.objects.get(name='UTF')
    else:
        UTF = Forum.objects.create(name='UTF')
    
    UTF.save()

    # Create all the ForumGroups
    if ForumGroup.objects.filter(name="Non présenté").exists():
        non_presente_group = ForumGroup.objects.get(name="Non présenté")
    else:
        non_presente_group = ForumGroup.objects.create(name="Non présenté", priority=10, description="""Personnes n'ayant pas encore posté leur présentation. POSTEZ-LA AU LIEU DE LIRE ÇA""",
        is_messages_group=True, minimum_messages=0, color="#808383")
        
    non_presente_group.save()
    
    if ForumGroup.objects.filter(name="Nouveau garde de nuit").exists():
        nouveau_garde_groupe = ForumGroup.objects.get(name="Nouveau garde de nuit")
    else:
        nouveau_garde_groupe = ForumGroup.objects.create(name="Nouveau garde de nuit", priority=20, description="""Membres inscrits récemment.""",
        is_messages_group=True, minimum_messages=1, color="#FFFFFF")
        
    nouveau_garde_groupe.save()

    if ForumGroup.objects.filter(name="Employé").exists():
        employe_group = ForumGroup.objects.get(name="Employé")
    else:
        employe_group = ForumGroup.objects.create(name="Employé", priority=30, description="""Membres actifs.
(Plus de 30 messages)""", is_messages_group=True, minimum_messages=30, color="#A1D384")
        
    employe_group.save()
        
    if ForumGroup.objects.filter(name="Animatronique").exists():
        animatronique_group = ForumGroup.objects.get(name="Animatronique")
    else:
        animatronique_group = ForumGroup.objects.create(name="Animatronique", priority=40, description="""Membres ayant plus de 60 messages.""",
        is_messages_group=True, minimum_messages=60, color="#33AD6D")

    animatronique_group.save()

        
    if ForumGroup.objects.filter(name="Springlock").exists():
        springlock_group = ForumGroup.objects.get(name="Springlock")
    else:
        springlock_group = ForumGroup.objects.create(name="Springlock", priority=50, description="""Membres très investis.
(Plus de 150 messages)""", is_messages_group=True, minimum_messages=150, color="#04BDBD")
        
    springlock_group.save()

        
    if ForumGroup.objects.filter(name="Théoricien").exists():
        theoricien_group = ForumGroup.objects.get(name="Théoricien")
    else:
        theoricien_group = ForumGroup.objects.create(name="Théoricien", priority=60, description="""Membres actifs s'investissant beaucoup dans les théories. (Ne floodez pas la section Théories avec des théories baclées juste pour obtenir ce grade, ça se voit)""",
        is_messages_group=False, minimum_messages=999999, color="#FFB200")
    
    theoricien_group.save()

        
    if ForumGroup.objects.filter(name="Modérateur").exists():
        moderateur_group = ForumGroup.objects.get(name="Modérateur")
    else:
        moderateur_group = ForumGroup.objects.create(name="Modérateur", priority=70, description="""Cherchez pas à rejoindre, vu le nombre de membres actuel, il y a pas grand-chose à modérer. :chica:""",
        is_messages_group=False, is_staff_group=True, minimum_messages=999999, color="#F40400")
    
    moderateur_group.save()
        
    if ForumGroup.objects.filter(name="Administrateur").exists():
        admin_group = ForumGroup.objects.get(name="Administrateur")
    else:
        admin_group = ForumGroup.objects.create(name="Administrateur", priority=80, description="""On est des dieux.""",
        is_messages_group=False, is_staff_group=True, minimum_messages=999999, color="#B10000")
    
    admin_group.save()

    # Create the User with a hashed password
    admin = User.objects.create_user(
        username=admin_username,  # Loaded from .env file
        password=env_password,  # Loaded from .env file
        email='admin@fake.com',
        is_staff=True,
        is_superuser=True,
    )

    # Create the Profile linked to the User
    Profile.objects.create(
        user=admin,
        birthdate=timezone.now().replace(year=2000, month=1, day=1),  # Fake dates
        gender='male',
    )

    # Add admin to 
    admin.profile.groups.add(non_presente_group, nouveau_garde_groupe, employe_group, animatronique_group, springlock_group, theoricien_group, moderateur_group, admin_group)
    admin.save()
    admin.profile.save()

    # Create the default categories
    if Category.objects.filter(name="Présentation").exists():
        presentation_category = Category.objects.get(name="Présentation")
    else:
        presentation_category = Category.objects.create(name="Présentation", slug="Pr-sentation")

    if Category.objects.filter(name="Five Nights At Freddy's").exists():
        fnaf_category = Category.objects.get(name="Five Nights At Freddy's")
    else:
        fnaf_category = Category.objects.create(name="Five Nights At Freddy's", slug="five-nights-at-freddy-s")

    if Category.objects.filter(name="Les jeux").exists():
        jeux_category = Category.objects.get(name="Les jeux")
    else:
        jeux_category = Category.objects.create(name="Les jeux", slug="Les-jeux")

    if Category.objects.filter(name="admin_only").exists():
        admin_only_category = Category.objects.get(name="admin_only")
    else:
        admin_only_category = Category.objects.create(name="admin_only", slug="admin_only", is_hidden=True)

    # Create the default subforums

    # Présentation
    if Topic.objects.filter(title="Présente-toi ici !").exists():
        presente_toi_subforum = Topic.objects.get(title="Présente-toi ici !")
    else:
        presente_toi_subforum = Topic.objects.create(author=admin,
                                           title="Présente-toi ici !",
                                           description="Pour pouvoir être activé, tu dois te présenter.",
                                           slug="Pr-sente-toi-ici",
                                           category=presentation_category,
                                           is_sub_forum=True,
                                           is_locked=False,
                                           is_index_topic=True)

        
    # Five Nights At Freddy's
    if Topic.objects.filter(title="Théories").exists():
        theories_subforum = Topic.objects.get(title="Théories")
    else:
        theories_subforum = Topic.objects.create(author=admin,
                                           title="Théories",
                                           description="Venez présenter vos théories ! Pour les théories sur les fangames, mettez une [balise] contenant le nom du jeu dans le titre.",
                                           slug="Th-ories",
                                           category=fnaf_category,
                                           is_sub_forum=True,
                                           is_index_topic=True)
        
    if Topic.objects.filter(title="Animatroniques").exists():
        animatroniques_subforum = Topic.objects.get(title="Animatroniques")
    else:
        animatroniques_subforum = Topic.objects.create(author=admin,
                                           title="Animatroniques",
                                           description="Blabla sur les animatroniques.",
                                           slug="Animatroniques",
                                           category=fnaf_category,
                                           is_sub_forum=True,
                                           is_index_topic=True)
        
    if Topic.objects.filter(title="Dessins et Fanarts").exists():
        dessins_subforum = Topic.objects.get(title="Dessins et Fanarts")
    else:
        dessins_subforum = Topic.objects.create(author=admin,
                                           title="Dessins et Fanarts",
                                           description="Montrez-nous vos dessins et Fanarts de Five Nights at Freddy's. Venez les poster ici !",
                                           slug="Dessins",
                                           category=fnaf_category,
                                           is_sub_forum=True,
                                           is_index_topic=True)
        
    
        
    # Les jeux
    if Topic.objects.filter(title="Five Nights At Freddy's").exists():
        fnaf_1_subforum = Topic.objects.get(title="Five Nights At Freddy's")
    else:
        fnaf_1_subforum = Topic.objects.create(author=admin,
                                           title="Five Nights At Freddy's",
                                           description="Discussions sur FNaF 1: gameplay, astuces, etc.",
                                           slug="Five-Nights-At-Freddy-s",
                                           category=jeux_category,
                                           is_sub_forum=True,
                                           is_index_topic=True)
        
    if Topic.objects.filter(title="Five Nights At Freddy's 2").exists():
        fnaf_2_subforum = Topic.objects.get(title="Five Nights At Freddy's 2")
    else:
        fnaf_2_subforum = Topic.objects.create(author=admin,
                                           title="Five Nights At Freddy's 2",
                                           description="Discussions sur FNaF 2: gameplay, astuces, etc.",
                                           slug="Five-Nights-At-Freddy-s-2",
                                           category=jeux_category,
                                           is_sub_forum=True,
                                           is_index_topic=True)
        
    if Topic.objects.filter(title="Five Nights At Freddy's 3").exists():
        fnaf_3_subforum = Topic.objects.get(title="Five Nights At Freddy's 3")
    else:
        fnaf_3_subforum = Topic.objects.create(author=admin,
                                           title="Five Nights At Freddy's 3",
                                           description="Discussions sur FNaF 3: gameplay, astuces, etc.",
                                           slug="Five-Nights-At-Freddy-s-3",
                                           category=jeux_category,
                                           is_sub_forum=True,
                                           is_index_topic=True)
        
    if Topic.objects.filter(title="Five Nights At Freddy's 4").exists():
        fnaf_4_subforum = Topic.objects.get(title="Five Nights At Freddy's 4")
    else:
        fnaf_4_subforum = Topic.objects.create(author=admin,
                                           title="Five Nights At Freddy's 4",
                                           description="Discussions sur FNaF 4.",
                                           slug="Five-Nights-At-Freddy-s-4",
                                           category=jeux_category,
                                           is_sub_forum=True,
                                           is_index_topic=True)
        
    if Topic.objects.filter(title="FNaF World").exists():
        fnaf_world_subforum = Topic.objects.get(title="FNaF World")
    else:
        fnaf_world_subforum = Topic.objects.create(author=admin,
                                           title="FNaF World",
                                           description="Discussions sur le RPG FNaF World !",
                                           slug="FNaF-World",
                                           category=jeux_category,
                                           is_sub_forum=True,
                                           is_index_topic=True)
        
    if Topic.objects.filter(title="Les Fan-Games").exists():
        fangames_subforum = Topic.objects.get(title="Les Fan-Games")
    else:
        fangames_subforum = Topic.objects.create(author=admin,
                                           title="Les Fan-Games",
                                           description="Discussions sur les fangames de Five Nights at Freddy's.",
                                           slug="Copies-du-jeu",
                                           category=jeux_category,
                                           is_sub_forum=True,
                                           is_index_topic=True)
        
    if Topic.objects.filter(title="Sister Location").exists():
        sister_location_subforum = Topic.objects.get(title="Sister Location")
    else:
        sister_location_subforum = Topic.objects.create(author=admin,
                                           title="Sister Location",
                                           description="Le spinoff de Five Nights at Freddy's, Sister Location.",
                                           slug="Sister-Location",
                                           category=jeux_category,
                                           is_sub_forum=True,
                                           is_index_topic=True) 
        
        
    # Create the default topics

    if Topic.objects.filter(title="Modèle de présentation").exists():
        presentation_topic = Topic.objects.get(title="Modèle de présentation")
    else:
        presentation_topic = Topic.objects.create(author=admin,
                                           title="Modèle de présentation",
                                           slug="Mod-le-de-pr-sentation",
                                           category=presentation_category,
                                           parent=presente_toi_subforum,
                                           is_sub_forum=False,
                                           is_locked=True,
                                           is_pinned=True,
                                           is_announcement=False,
                                           is_index_topic=False,
                                           )
        
        
    # Create the default posts

    if Post.objects.filter(text="""Modèle de présentation (vous n'êtes en aucun cas obligés de le suivre):

[b][u]Prénom:[/u][/b]

[b][u]Âge:[/u][/b]

[b][u]Loisirs:[/u][/b]



Si vous avez déjà joué à FNaF:
[b][u]Opus préféré de FNaF:[/u][/b]


[b][u]Personnage préféré de FNaF:[/u][/b]



[b][u]Question/Remarque/Commentaire:[/u][/b]





Votre présentation est à poster ici en cliquant sur "NOUVEAU POST".""",author=admin).exists():
        presentation_post = Post.objects.get(text="""Modèle de présentation (vous n'êtes en aucun cas obligés de le suivre):

[b][u]Prénom:[/u][/b]

[b][u]Âge:[/u][/b]

[b][u]Loisirs:[/u][/b]



Si vous avez déjà joué à FNaF:
[b][u]Opus préféré de FNaF:[/u][/b]


[b][u]Personnage préféré de FNaF:[/u][/b]



[b][u]Question/Remarque/Commentaire:[/u][/b]





Votre présentation est à poster ici en cliquant sur "NOUVEAU POST".""",author=admin)
    else:
        presentation_post = Post.objects.create(author=admin,
                                           topic=presentation_topic,
                                           text="""Modèle de présentation (vous n'êtes en aucun cas obligés de le suivre):

[b][u]Prénom:[/u][/b]

[b][u]Âge:[/u][/b]

[b][u]Loisirs:[/u][/b]



Si vous avez déjà joué à FNaF:
[b][u]Opus préféré de FNaF:[/u][/b]


[b][u]Personnage préféré de FNaF:[/u][/b]



[b][u]Question/Remarque/Commentaire:[/u][/b]





Votre présentation est à poster ici en cliquant sur "NOUVEAU POST".""")
        
    # Save everything just in case
    non_presente_group.save()
    nouveau_garde_groupe.save()
    employe_group.save()
    animatronique_group.save()
    springlock_group.save()
    theoricien_group.save()
    moderateur_group.save()
    admin_group.save()
    presentation_category.save()
    fnaf_category.save()
    jeux_category.save()
    admin_only_category.save()
    presente_toi_subforum.save()
    theories_subforum.save()
    animatroniques_subforum.save()
    dessins_subforum.save()
    fnaf_1_subforum.save()
    fnaf_2_subforum.save()
    fnaf_3_subforum.save()
    fnaf_4_subforum.save()
    fnaf_world_subforum.save()
    fangames_subforum.save()
    sister_location_subforum.save()
    presentation_topic.save()
    presentation_post.save()

    for topic in Topic.objects.all():
        topic.total_replies += 1
        if topic.is_index_topic:
            topic.category.index_topics.add(topic)
            topic.category.save()
        if topic.is_sub_forum == False:
            current = topic.parent
            while current != None:
                current.total_children += 1
                current.save()
                current = current.parent
            topic.total_replies -= 1
        topic.save()

    for post in Post.objects.all():
        current = post.topic
        while current != None:
            current.total_replies += 1
            current.save()
            current = current.parent

    admin.profile.messages_count += 1
    admin.profile.save()
    UTF.total_messages += 1
    UTF.total_users += 1
    UTF.save()


class Migration(migrations.Migration):

    dependencies = [
        ('forum', '0046_remove_profile_desc_remove_profile_favorite_games_and_more'),
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.RunPython(create_user_and_profile, migrations.RunPython.noop),
    ]
